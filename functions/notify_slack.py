import base64
import json
import logging
import os
import urllib.parse
import urllib.request
from urllib.error import HTTPError

import boto3
from botocore.exceptions import ClientError


logger = logging.getLogger(__name__)


# Decrypt encrypted URL with KMS
def decrypt(encrypted_url):
    region = os.environ['AWS_REGION']
    kms = boto3.client('kms', region_name=region)
    try:
        plaintext = kms.decrypt(CiphertextBlob=base64.b64decode(encrypted_url))['Plaintext']
    except ClientError as ex:
        logger.exception(ex)
    return plaintext.decode()


def cloudwatch_notification(message, region):
    states = {'OK': 'good', 'INSUFFICIENT_DATA': 'warning', 'ALARM': 'danger'}

    console_url = f'https://console.aws.amazon.com/cloudwatch/home?region={region}'
    return {
        'color': states[message['NewStateValue']],
        'fallback': 'Alarm {} triggered'.format(message['AlarmName']),
        'fields': [
            {'title': 'Alarm Name', 'value': message['AlarmName'], 'short': True},
            {'title': 'Alarm Description', 'value': message['AlarmDescription'], 'short': False},
            {'title': 'Alarm reason', 'value': message['NewStateReason'], 'short': False},
            {'title': 'Old State', 'value': message['OldStateValue'], 'short': True},
            {'title': 'Current State', 'value': message['NewStateValue'], 'short': True},
            {
                'title': 'Link to Alarm',
                'value':  console_url + '#alarm:alarmFilter=ANY;name=' + urllib.parse.quote(message['AlarmName']),
                'short': False
            },
        ],
    }


def codepipeline_approval(message):
    """Uses Slack's Block Kit."""
    console_link = message['consoleLink']
    approval = message['approval']
    pipeline_name = approval['pipelineName']
    action_name = approval['actionName']
    approval_review_link = approval['approvalReviewLink']
    expires = approval['expires']

    return {
        'color': '#00D0FF',
        'blocks': (
            {
                'type': 'section',
                'text': {
                    'type': 'plain_text',
                    'text': f'Pipeline "{pipeline_name}" is waiting for approval.',
                },
                'accessory': {
                    'type': 'button',
                    'text': {
                        'type': 'plain_text',
                        'text': 'Open in :aws: Console',
                        'emoji': True,
                    },
                    'url': console_link,
                },
            },
            {
                'type': 'section',
                'fields': [
                    {
                        'type': 'mrkdwn',
                        'text': f'*Action name*:\n{action_name}',
                    },
                    {
                        'type': 'mrkdwn',
                        'text': f'*Expires:* {expires}',
                    },
                ],
            },
            {
                'type': 'actions',
                'elements': [
                    {
                        'type': 'button',
                        'text': {
                            'type': 'plain_text',
                            'emoji': False,
                            'text': 'Review approve',
                        },
                        'style': 'primary',
                        'url': approval_review_link,
                    },
                ],
            },
        )
    }


def codepipeline_detail(message):
    """Uses Slack's Block Kit."""
    def get_emoji(state):
        states = {
            'CANCELLED': ('#9D9D9D', ':grey_exclamation:'),  # grey
            'FAILED': ('#D10C20', ':x:'),
            'RESUMED': ('#006234', ':recycle:'),  # dark green
            'STARTED': ('#0059C6', ':information_source:'),  # blue
            'SUCCEEDED': ('#41AA58', ':heavy_check_mark:'),
            'SUPERSEDED': ('#DAA038', ':heavy_minus_sign:'),
        }
        return states.get(state, ('#DAA038', ':grey_question:'))

    time = message['time']
    detail = message['detail']
    pipeline = detail['pipeline']
    execution_id = detail['execution-id']
    state = detail['state']
    color, emoji = get_emoji(state)

    return {
        'color': color,
        'blocks': (
            {
                'type': 'section',
                'text': {
                    'type': 'plain_text',
                    'emoji': True,
                    'text': f'{emoji} {state.capitalize()} pipeline "{pipeline}".',
                },
            },
            {
                'type': 'section',
                'fields': [
                    {
                        'type': 'mrkdwn',
                        'text': f'*State:*\n{state}',
                    },
                    {
                        'type': 'mrkdwn',
                        'text': f'*Execution ID:*\n`{execution_id}`',
                    },
                ],
            },
            {
                'type': 'context',
                'elements': [
                    {
                        'type': 'mrkdwn',
                        'text': f'*Timestamp:* {time}',
                    },
                ],
            },
        ),
    }


def codepipeline_notification(event):
    if isinstance(event, str):
        event = json.loads(event)

    if 'approval' in event:
        notification = codepipeline_approval(event)
    if 'detail' in event:
        notification = codepipeline_detail(event)

    return notification


def default_notification(subject, message):
    return {
        'fallback': 'A new message',
        'fields': [
            {
                'title': subject if subject else 'Message',
                'value': json.dumps(message) if isinstance(message, dict) else message,
                'short': False,
            },
        ],
    }


# Send a message to a Slack channel
def notify_slack(subject, message, region):
    slack_url = os.environ['SLACK_WEBHOOK_URL']
    if not slack_url.startswith('http'):
        slack_url = decrypt(slack_url)

    slack_channel = os.environ['SLACK_CHANNEL']
    slack_username = os.environ['SLACK_USERNAME']
    slack_emoji = os.environ['SLACK_EMOJI']

    payload = {
        'channel': slack_channel,
        'username': slack_username,
        'icon_emoji': slack_emoji,
        'attachments': [],
    }

    if isinstance(message, str):
        try:
            message = json.loads(message)
        except json.JSONDecodeError as ex:
            logger.exception(ex)

    if 'AlarmName' in message:
        notification = cloudwatch_notification(message, region)
        payload['text'] = 'AWS CloudWatch notification - ' + message['AlarmName']
        payload['attachments'].append(notification)
    elif 'approval' in message or 'detail' in message:
        notification = codepipeline_notification(message)
        payload['attachments'].append(notification)
    else:
        payload['text'] = 'AWS notification'
        payload['attachments'].append(default_notification(subject, message))

    data = urllib.parse.urlencode({'payload': json.dumps(payload)}).encode('utf-8')
    req = urllib.request.Request(slack_url)

    try:
        result = urllib.request.urlopen(req, data)
        return json.dumps({'code': result.getcode(), 'info': result.info().as_string()})
    except HTTPError as ex:
        logger.exception(ex)
        return json.dumps({'code': ex.getcode(), 'info': ex.info().as_string()})


def lambda_handler(event, context):
    if 'LOG_EVENTS' in os.environ and os.environ['LOG_EVENTS'] == 'True':
        logger.warning('Event logging enabled: "%s"', json.dumps(event))

    subject = event['Records'][0]['Sns']['Subject']
    message = event['Records'][0]['Sns']['Message']
    region = event['Records'][0]['Sns']['TopicArn'].split(':')[3]
    response = notify_slack(subject, message, region)

    if json.loads(response)['code'] != 200:
        logger.error('Error: received status "%s" using event "%s" and context "%s"',
                     json.loads(response)['info'], event, context)

    return response
