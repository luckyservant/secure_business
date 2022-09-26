'''
AWS IAM BASIC CHECKS
Developed by umit.sadeguzel
#Find console users with no MFA
#Find idle console users
#Find idle acckey users
#Find keys to rotate
#Find users with both acckey and console access
#Find users with inline policy
# Any role or service(TrustedEntities,EC2,RDS) but root account can not have roles such as S3 full (AmazonS3FullAccess), admin (AdministratorAccess) access --> IAM Roles
#
'''
import json
from botocore.vendored import requests
from multiprocessing import Process, Pipe
from datetime import datetime
import boto3
import urllib3
import botocore.exceptions
import os
from multiprocessing.pool import ThreadPool
import itertools

# To do:
# et hook env.
channel_webhook = os.environ['CHANNEL_WEBHOOK']
date_now = datetime.now()
iam_client = boto3.client('iam')
max_idle_days = 90  # to do --> fetch from user policy
max_items = 50
toleranced_creation_days = 90  # to do --> fetch from user policy
acckey_rotate_day_limit = 60  # to do --> fetch from user policy
report_bucket_name = 'your.bucket.name'
report_output_arr = []
console_users = []
acckey_users = []
# list IAM users
users = iam_client.list_users()  # fetch all IAM users


# region list users with inline policy
def list_user_with_inline_policy(iam_users):
    users_with_inline_policy = []
    for user in iam_users['Users']:
        if (iam_client.list_user_policies(UserName=user.get("UserName")).get("PolicyNames")):
            users_with_inline_policy.append(user.get("UserName"))

    return users_with_inline_policy


def list_users_with_priviliged_roles(iam_users):
    users_with_inline_policy = []
    for user in iam_users['Users']:
        if (iam_client.list_user_policies(UserName=user.get("UserName")).get("PolicyNames")):
            users_with_inline_policy.append(user.get("UserName"))

    return users_with_inline_policy


# endregion
# region mfa checks
def is_user_mfa_enabled(user_name):
    '''
        Returns if given user is mfa enabled

                Parameters:
                        user_name (str): user name to check mfa
                Returns:
                        mfa_enabled (Boolean): Returns a Boolean value indicating whether the user has enabled MFA
        '''
    mfa_enabled = False
    mfa_check = iam_client.list_mfa_devices(UserName=user_name)
    if (mfa_check and mfa_check.get("MFADevices")):
        mfa_enabled = True
    return mfa_enabled


def find_mfa_enabled_console_users(iam_users):
    global console_users
    if (not console_users):
        console_users = find_console_users(iam_users)
    mfa_enabled_console_users = []
    mfa_enabled = False
    for user in console_users:
        mfa_enabled = is_user_mfa_enabled(user.get("UserName"))
        if (mfa_enabled):
            mfa_enabled_console_users.append(user.get("UserName"))
    return mfa_enabled_console_users


def find_console_users_not_mfa_enabled(console_users):
    missing_mfa_console_users = []
    mfa_enabled = False
    for user in console_users:
        mfa_enabled = is_user_mfa_enabled(user.get("UserName"))
        if (not (mfa_enabled)):
            missing_mfa_console_users.append(user.get("UserName"))
    return missing_mfa_console_users


# endregion
# region console user operations
def find_console_users(iam_users):  # users having PasswordLastUsed field or with no PasswordLastUsed and no accesskey
    global console_users
    users_with_no_password = []
    console_users_with_no_password = []
    users_having_both_console_accesskey = []
    for user in iam_users['Users']:
        if (
                'PasswordLastUsed' not in user):  # If the PasswordLastUsed is missing, then the user either has no password or the password has not been used
            no_pwd_user_dict = {"UserName": user.get("UserName"), "CreateDate": user.get("CreateDate")}
            users_with_no_password.append(no_pwd_user_dict)
        if ('PasswordLastUsed' in user):  #
            user_dict = {"UserName": user.get("UserName"), "CreateDate": user.get("CreateDate"),
                         "PasswordLastUsed": user.get("PasswordLastUsed")}
            console_users.append(user_dict)
    for no_pwd_user in users_with_no_password:  # is it due to users with no passwords are actually an accesskey users
        user_access_keys = iam_client.list_access_keys(UserName=no_pwd_user.get("UserName"))
        no_pwd_user_dict = {"UserName": no_pwd_user.get("UserName"), "CreateDate": no_pwd_user.get("CreateDate")}
        if not (user_access_keys.get("AccessKeyMetadata")):
            console_users_with_no_password.append(no_pwd_user)
            console_users.append(no_pwd_user_dict)

    return console_users


def find_if_user_can_login(user_name):
    result = False
    try:
        iam_client.get_login_profile(UserName=user_name)
        result = True
    except botocore.exceptions.ClientError as ex:
        if ex.response['Error']['Code'] == 'NoSuchEntityException':
            result = False

    return result


def find_idle_console_users(iam_users):
    # > 30 gun mu. kucukse ignore ,90 gün icinde login olmamissa alert uret
    idle_console_users = []
    global console_users
    if (not console_users):
        console_users = find_console_users(iam_users)
    for user in console_users:
        creation_date = user.get('CreateDate').replace(tzinfo=None)  # YYYY MM DD
        creation_difference = date_now - creation_date
        if ('PasswordLastUsed' not in user and creation_difference.days > toleranced_creation_days and user.get(
                "UserName") not in idle_console_users):  # Ignore users created before 1 month
            idle_console_users.append(user.get('UserName'))
        if ('PasswordLastUsed' in user):  #
            # print(user)
            last_used_date = user.get('PasswordLastUsed').replace(tzinfo=None)  # YYYY MM DD
            difference = date_now - last_used_date
            if difference.days > max_idle_days and user.get("UserName") not in idle_console_users:
                idle_console_users.append(user['UserName'])

    return idle_console_users


# endregion
# region polygot users
def find_polygot_users(iam_users):
    global console_users
    if (not console_users):
        console_users = find_console_users(iam_users)
    users_having_both_console_accesskey = []
    for pwd_user in console_users:
        user_pwd_access_keys = iam_client.list_access_keys(UserName=pwd_user.get("UserName"))
        user_keys = user_pwd_access_keys.get("AccessKeyMetadata")
        if (user_keys):
            no_pwd_user_dict = {"UserName": pwd_user.get("UserName"), "AccessKeyId": user_keys[0].get("AccessKeyId"),
                                "CreateDate": pwd_user.get("CreateDate")}
            users_having_both_console_accesskey.append(no_pwd_user_dict)
    return users_having_both_console_accesskey


# endregion
# region acckey user operations
# find users both having access keys with key status either Active or Inactive and console users with an access key
def find_access_key_users(iam_users):
    global console_users
    if (not console_users):
        console_users = find_console_users(iam_users)
    users_with_no_password = []
    users_with_access_key = []
    # return iam_users.get("Users")
    diff_allusers_and_console_users = [i for i in iam_users.get("Users") if i.values() not in console_users]
    for no_pwd_user in diff_allusers_and_console_users:  # is it due to users with no passwords are actually an accesskey users
        user_access_keys = iam_client.list_access_keys(UserName=no_pwd_user.get("UserName"))
        if (user_access_keys.get("AccessKeyMetadata")):
            # users_with_access_key = None
            for acckey in user_access_keys.get("AccessKeyMetadata"):
                AccessKeyLastUsedDate = iam_client.get_access_key_last_used(AccessKeyId=acckey.get("AccessKeyId")).get(
                    "AccessKeyLastUsed").get("LastUsedDate")
                no_pwd_user_dict = {"UserName": no_pwd_user.get("UserName"), "AccessKeyId": acckey.get("AccessKeyId"),
                                    "Status": acckey.get("Status"), "LastUsedDate": AccessKeyLastUsedDate,
                                    "CreateDate": acckey.get("CreateDate")}
                if (no_pwd_user_dict not in users_with_access_key):
                    users_with_access_key.append(no_pwd_user_dict)
    return users_with_access_key  # list({v['UserName']:v for v in users_with_access_key}.values())#eleminate duplicates


'''
 access keys not utilized within 90 days
'''


def find_idle_acckey_users(iam_users):
    idle_acckey_users = []
    global acckey_users
    if (not acckey_users):
        acckey_users = find_access_key_users(iam_users)
    # print(acckey_users)
    for user in acckey_users:
        creation_date = user.get('CreateDate').replace(tzinfo=None)  # YYYY MM DD
        creation_difference = date_now - creation_date
        if (creation_difference.days > toleranced_creation_days):  # Ignore user if created less than 1 month
            '''
            iam_client.get_access_key_last_used
            Happy Response Model--> {'UserName': 'xyz.acckey', 'AccessKeyLastUsed': {'LastUsedDate': datetime.datetime(2022, 4, 27, 20, 46, tzinfo=tzutc()), 'ServiceName': 'iam', 'Region': 'us-east-1'}, 'ResponseMetadata': {'RequestId': '9737', 'HTTPStatusCode': 200, 'HTTPHeaders': {'x-amzn-requestid': '24d9737', 'content-type': 'text/xml', 'content-length': '505', 'date': 'Wed, 27 Apr 2022 20:55:22 GMT'}, 'RetryAttempts': 0}}
            Sad Response Model-->   {'UserName': 'joe.doe', 'AccessKeyLastUsed': {'ServiceName': 'N/A', 'Region': 'N/A'}, 'ResponseMetadata': {'RequestId': '2a12fe77b177', 'HTTPStatusCode': 200, 'HTTPHeaders': {'x-amzn-requestid': '77b177', 'content-type': 'text/xml', 'content-length': '440', 'date': 'Wed, 27 Apr 2022 20:46:03 GMT'}, 'RetryAttempts': 0}}            
            '''
            idle_user_dict = {}
            # acckey_meta_dict = iam_client.get_access_key_last_used(AccessKeyId=user.get("AccessKeyId"))
            if (user.get("LastUsedDate") is None):
                idle_user_dict = {"UserName": user.get("UserName"), "AccessKeyId": user.get("AccessKeyId"),
                                  "Status": user.get("Status")}
                idle_acckey_users.append(idle_user_dict)
                # print(f"gelen deger{acckey_meta_dict}")
            else:
                difference = date_now - user.get("LastUsedDate").replace(tzinfo=None)
                if difference.days > max_idle_days:
                    idle_user_dict = {"UserName": user.get("UserName"), "AccessKeyId": user.get("AccessKeyId"),
                                      "Status": user.get("Status")}
                    idle_acckey_users.append(idle_user_dict)
    return idle_acckey_users


'''
list active keys
'''


def find_active_acckey_users(iam_users):
    users_with_access_key = []
    global acckey_users
    if (not acckey_users):
        acckey_users = find_access_key_users(iam_users)
    for acckey_user in acckey_users:  # is it due to users with no passwords are actually an accesskey users
        user_access_keys = iam_client.list_access_keys(UserName=acckey_user.get("UserName"))
        if (user_access_keys.get("AccessKeyMetadata")):
            for acckey in user_access_keys.get("AccessKeyMetadata"):
                if (acckey.get("Status") == "Active"):
                    AccessKeyLastUsedDate = iam_client.get_access_key_last_used(
                        AccessKeyId=acckey.get("AccessKeyId")).get("AccessKeyLastUsed").get("LastUsedDate")
                    acckey_user_dict = {"UserName": acckey_user.get("UserName"),
                                        "AccessKeyId": acckey.get("AccessKeyId"),
                                        "AccessKeyLastUsedDate": AccessKeyLastUsedDate,
                                        "CreateDate": acckey_user.get("CreateDate")}
                    if (acckey_user_dict not in users_with_access_key):
                        users_with_access_key.append(acckey_user_dict)
    return list({v['UserName']: v for v in users_with_access_key}.values())  # eleminate duplicates


'''
list inactive keys
'''


def find_inactive_acckey_users(iam_users):
    users_with_access_key = []
    global acckey_users
    if (not acckey_users):
        acckey_users = find_access_key_users(iam_users)
    for acckey_user in acckey_users:  # is it due to users with no passwords are actually an accesskey users
        user_access_keys = iam_client.list_access_keys(UserName=acckey_user.get("UserName"))
        if (user_access_keys.get("AccessKeyMetadata")):
            for acckey in user_access_keys.get("AccessKeyMetadata"):
                if (acckey.get("Status") == "Inactive"):
                    AccessKeyLastUsedDate = iam_client.get_access_key_last_used(
                        AccessKeyId=acckey.get("AccessKeyId")).get("AccessKeyLastUsed").get("LastUsedDate")
                    acckey_user_dict = {"UserName": acckey_user.get("UserName"),
                                        "AccessKeyId": acckey.get("AccessKeyId"),
                                        "AccessKeyLastUsedDate": AccessKeyLastUsedDate,
                                        "CreateDate": acckey_user.get("CreateDate")}
                    if (acckey_user_dict not in users_with_access_key):
                        users_with_access_key.append(acckey_user_dict)
    return list({v['UserName']: v for v in users_with_access_key}.values())  # eleminate duplicates


'''
 keys utilized in last 90 days but creation date > 90 days need to be rotated
'''


def find_acckeys_to_rotate(iam_users):
    # > 30 gun mu. kucukse ignore ,90 gün icinde login olmamissa alert uret
    acckeys_to_rotate = []
    global acckey_users
    if (not acckey_users):
        acckey_users = find_access_key_users(iam_users)
    # idle_acckey_users= find_idle_acckey_users(iam_users)
    # print(idle_acckey_users)
    diff_of_two_list = []
    # diff_of_two_list= [i for i in acckey_users if i.values() not in idle_acckey_users]
    # print(diff_of_two_list)
    for user in acckey_users:
        creation_date = user.get('CreateDate').replace(tzinfo=None)
        creation_difference = date_now - creation_date
        if (user.get('LastUsedDate') is not None):
            last_used_date = user.get('LastUsedDate').replace(tzinfo=None)  # YYYY MM DD
            lastused_date_difference = date_now - last_used_date
            if (lastused_date_difference.days < max_idle_days and creation_difference.days > toleranced_creation_days):
                rotation_key_dict = {'UserName': user.get("UserName"), 'AccessKeyId': user.get('AccessKeyId'),
                                     "Status": user.get("Status")}
                acckeys_to_rotate.append(rotation_key_dict)

    return acckeys_to_rotate


# endregion

# region select_from_list_of_dicts
def select_from_list_of_dicts(dict_list, *selected_fields):
    filtered_dict_list = []
    for dict_row in dict_list:
        filtered_dict = {k: v for k, v in zip(selected_fields, dict_row.values())}
        filtered_dict_list.append(filtered_dict)

    return filtered_dict_list


# endregion

def acckeyusers_not_in_fg_group(iam_users):
    users_without_group = []
    global acckey_users
    if (not acckey_users):
        acckey_users = find_access_key_users(iam_users)
    fg_accesskey_users = get_users_in_group("FG_AllAccessKeyUsers")

    for acckey_user in acckey_users:
        if (acckey_user.get("UserName") not in fg_accesskey_users):
            users_without_group.append(acckey_user.get("UserName"))
    return users_without_group


def get_users_in_group(group_name):
    group = boto3.resource('iam').Group(group_name)
    name_list = []
    for fg_user in group.users.all():
        name_list.append(fg_user.name)
    return name_list


# region slack notifications
def send_slack_notifications(message):
    if (channel_webhook):
        report_url = f"https://s3.eu-central-1.amazonaws.com/your-bucket-name/your-folder-path-{datetime.today().strftime('%Y-%m-%d')}.txt"
        slack_json_msg = {"text": "AWS IAM Alerts",
                          "blocks": [
                              {
                                  "type": "section",
                                  "block_id": "section567",
                                  "text": {
                                      "type": "mrkdwn",
                                      "text": f"{message}\n <{report_url}|Report Link> \n :skype_bell: \n "
                                  }
                              }
                          ]
                          }

    encoded_data = json.dumps(slack_json_msg).encode('utf-8')
    http = urllib3.PoolManager()
    r = http.request('POST', channel_webhook,
                     headers={'Content-Type': 'application/json'},
                     body=encoded_data)

    return r


# endregion

# region find true positives to push
def get_alert_needed_no_mfa_users(mfa_users):
    true_positives = []
    for mfa_user in mfa_users:
        if (find_if_user_can_login(mfa_user)):
            true_positives.append(mfa_user)
    return true_positives


def get_alert_needed_acckey_users(acckey_users):
    true_positives = []
    for acckey_user in acckey_users:
        if (acckey_user.get("Status") != "Inactive"):
            true_positives.append(acckey_user)
    return true_positives


def put_reports_to_s3(report_string):
    some_binary_data = b'Here we have some data'
    # Method 1: Object.put()
    body = report_string
    s3 = boto3.resource('s3')
    object = s3.Object(report_bucket_name, f'iam-reports/iam-reports-{datetime.today().strftime("%Y-%m-%d")}.txt')
    response = object.put(Body=body)
    return response


def build_report_string(identity_field, report_list):
    str = ""
    for row in report_list:
        if not isinstance(row, dict):
            str = row
            str = str + "," + identity_field
            report_output_arr.append(str)
        else:
            if (row.get("UserName") is not None):
                str = row.get("UserName") + ","
            if (row.get("AccessKeyId") is not None):
                str = str + row.get("AccessKeyId") + ","
            if (row.get("UserName") is not None):
                str = str + identity_field
            report_output_arr.append(str)


def get_report_output_arr():
    return "\n".join(report_output_arr)


def lambda_handler(event, context):
    # region build ntf messages
    ntf_msg = ""
    # console_users = thread_pool.apply_async(find_console_users,(users,)).get()
    # acckey_users = thread_pool2.apply_async(find_access_key_users,(users,) ).get()
    # create a list to keep all processes
    processes = []
    # create a list to keep connections
    parent_connections = []
    # create a process per instance

    # create a pipe for communication
    parent_conn, child_conn = Pipe()
    parent_connections.append(parent_conn)

    # create the process, pass instance and connection

    processes.append(Process(target=find_console_users, args=(users, child_conn,)))
    processes.append(Process(target=find_access_key_users, args=(users, child_conn,)))

    # start all processes
    for process in processes:
        process.start()

    # make sure that all processes have finished
    for process in processes:
        process.join()

    alert_required_mfa_users = get_alert_needed_no_mfa_users(find_console_users_not_mfa_enabled(console_users))
    alert_required_idle_acckey_users = get_alert_needed_acckey_users(find_idle_acckey_users(users))
    alert_required_rotation_key_users = get_alert_needed_acckey_users(find_acckeys_to_rotate(users))
    alert_required_idle_console_users = find_idle_console_users(users)
    alert_acckeyusers_notin_user_group = acckeyusers_not_in_fg_group(users)

    if (alert_required_mfa_users):
        ntf_msg = f"{len(alert_required_mfa_users)} users not MFA enabled \n"
        build_report_string("mfa_not_enabled", alert_required_mfa_users)

    if (alert_required_idle_acckey_users):
        ntf_msg = ntf_msg + "**************************** \n"
        ntf_msg = ntf_msg + f"{len(alert_required_idle_acckey_users)} users keys are idle \n"
        build_report_string("idle_acckey_users", alert_required_idle_acckey_users)

    if (alert_required_rotation_key_users):
        ntf_msg = ntf_msg + "**************************** \n"
        ntf_msg = ntf_msg + f"{len(alert_required_rotation_key_users)} users keys must be rotated \n"
        build_report_string("rotation_key_users", alert_required_rotation_key_users)

    if (alert_required_idle_console_users):
        ntf_msg = ntf_msg + "**************************** \n"
        ntf_msg = ntf_msg + f"{len(alert_required_idle_console_users)} console users are idle \n"
        build_report_string("idle_console_users", alert_required_idle_console_users)

    if (alert_acckeyusers_notin_user_group):
        ntf_msg = ntf_msg + "**************************** \n"
        ntf_msg = ntf_msg + f"{len(alert_acckeyusers_notin_user_group)} acckey users are not in FG_AcccessKey_Users group"
        build_report_string("acckeyusers_notin_user_group", alert_acckeyusers_notin_user_group)
    # endregion

    # region push reports to channels
    put_reports_to_s3(get_report_output_arr())
    send_slack_notifications(ntf_msg)
    # endregion

    return {
        'statusCode': 200,
        'body': json.dumps('Success')
    }
