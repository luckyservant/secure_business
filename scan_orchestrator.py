import hashlib
import os.path
import itertools
from itertools import count
import urllib
import base64
import operator
import json
import requests
from requests.auth import HTTPBasicAuth
from collections import Counter
import re
import time
import boto3
# from boto.s3.key import Key
import datetime as dt
from datetime import datetime

''''
!!!!!!Developed by Umit Sadeguzel Team!!!!!
Semgrep Scan Cmd : semgrep --config=auto -o semgrep_full_scan.json --json
Semgrep Lang Specific Scan Cmd: semgrep --config "p/secrets" -o ie_ondemand_secrets.json --jsonSelect from list of dicts cmd : liste= [item for item in results_to_relational_data_schema_dict_list if item["VulTechFamiy"] =="Secrets"  and "N\\-A" in item["Secret"] ]
'''
import requests
import json
import argparse

scan_path = "path"
# region constant configs
cur_date = str(dt.date.today())
jira_api_base_url = "https://xxx.atlassian.net/rest/api/latest"
jira_token = "jiratoken"
mend_api_url = "https://saas.whitesourcesoftware.com/api/v1.3"
mend_org_token = "mendtoken"
mend_userkey = "menduserkey"
sonar_token = "sonartoken"
jira_user = "jirauser@yourorg.com"
# headers = {'content-type': 'application/json'} requests.post(url, data=json.dumps(payload), headers=headers)
src_base_url = "https://src.xxx.com"
src_base_url_dict = {"app1": "https://src.xx.com/project/repo/source/-/blob/main/",
                     "app2": "https://src.xx.com/project/repo/source/-/tree/develop/app2",
                     "app3": "https://src.xx.com/project/repo/xx"
                     }
headers = {'Content-Type': 'application/json'}
jira_session = requests.Session()
jira_session.auth = (jira_user, jira_token)

sca_default_min_severity_to_report = 4
sast_default_min_severity_to_report = 2
sca_severity_levels_dict = {1: "LOW",
                            2: "WARNING",
                            3: "ERROR",
                            4: "MEDIUM",
                            5: "HIGH",
                            6: "CRITICAL"}

sast_severity_levels_dict = {1: "LOW",
                             2: "WARNING",
                             3: "ERROR",
                             4: "MEDIUM",
                             5: "HIGH",
                             6: "CRITICAL"}

sast_excluded_libs = ["jquery",
                      "tree.js",
                      "bootstrap",
                      "Bootstrap",
                      "knockout.js"
                      "Version Tables",
                      "sass",
                      "intlTelInput",
                      "highlight"]

sonar_project_list = ["proj1",
                      "proj2",
                      "proj3"]
branch_list = []
branch_name = "main"  # TO-DO get from env var
sca_tool_list = ["whitesource", "trivy"]
sast_tool_list = ["sonarqube", "semgrep"]
scan_tools = ["trivy", "semgrep", "whitesource", "sonarqube"]
jira_semgrep_duplicate_check_fields = ["Msg", "SourceInfo"]
jira_trivy_duplicate_check_fields = ["CVE", "PackageName"]
dictData = []
channel_webhook = os.environ['CHANNEL_WEBHOOK']
report_bucket_name = 'xx.reports'
parsed_result_2_slack = []
results_to_relational_data_schema_dict_list = []
input_file_paths_list = []
# endregion

# region util functions

'''
 This function traverses a json input (dict) and dynamically fetches key-value pairs
 How to Call:
        for key, value in recursive_items(dict_input):
            print(key, value)
'''
dthandler = lambda obj: obj.isoformat() if isinstance(obj, datetime) else json.JSONEncoder().default(obj)
def recursive_items(dictionary):
    for key, value in dictionary.items():
        if type(value) is dict:
            yield from recursive_items(value)
        else:
            yield (key, value)

# select needed fields from_list_of_dicts
def select_from_list_of_dicts(dict_list, *selected_fields):    
    filtered_dict_list = []
    for dict_row in dict_list:
        filtered_dict = dict((k, dict_row[k]) for k in selected_fields if k in dict_row.keys())
        filtered_dict_list.append(filtered_dict)    
    return filtered_dict_list

def check_file_size(file_path):
    return os.path.getsize(file_path)

def get_files_under_curdir():
    cur_date = dt.date.today()
    files = []
    path = os.walk(f"{scan_path}")
    for dirpath, _, filenames in path:
        for f in filenames:
            fpath = os.path.join(dirpath, f)
            fpath = fpath.replace("\\", "/")
            files.append(fpath)
    return files

def drop_prj_name_from_pckg_name(src_file):
    if (src_file.find("/") > 0):
        splitted_src_file = src_file.split("/")
        last_two = splitted_src_file[-2:]        
        return f"{last_two[0]}/{last_two[1]}"
    else:
        return src_file

def remove_duplicate_issues(vul_list):    
    sca_dup_counts = Counter(
        (d["Project"], d["Branch"], d["CVE"]) for d in vul_list if d.get("CVE") not in ("N-A", "None"))    
    # Remove duplicate SCA findings, group by Project,Branch,CVE
    for row_dict in list(vul_list):
        sca_dup_counts = Counter(
            (d["Project"], d["Branch"], d["CVE"]) for d in vul_list if d.get("CVE") not in ("N-A", "None"))
        sca_multiple_tool_keys = Counter((d["ScanType"], d["Project"], d["Branch"], d["CVE"]) for d in vul_list if
                                         d.get("CVE") not in ("N-A", "None"))
        del_flag = 0
        match_pattern = ""
        sca_cur_row_tuple = (row_dict.get("Project"), row_dict.get("Branch"), row_dict.get("CVE"))
        sca_confirmation_tuple = (
        row_dict.get("Project"), row_dict.get("Branch"), row_dict.get("CVE"), row_dict.get("MatchPkg"),
        row_dict.get("ScanType"))
        if (row_dict.get("CVE") not in ("N-A", "None") and sca_dup_counts[sca_cur_row_tuple] > 1):
            del_flag = 1
        if (del_flag == 1):
            vul_list.remove(row_dict)
            for inx, row in enumerate(vul_list):
                if (row.get("Project") == sca_confirmation_tuple[0] and
                        row.get("Branch") == sca_confirmation_tuple[1] and
                        row.get("CVE") == sca_confirmation_tuple[2] and
                        row.get("ScanType") != sca_confirmation_tuple[4]):
                    if("Confirmed by multiple tools" not in vul_list[inx]['Msg']):
                        vul_list[inx]['Msg'] = vul_list[inx]['Msg'] + f" \n !!!Confirmed by multiple tools!!!"

    # Remove duplicate SAST findings.Group by["Project"], d["Branch"], d["MatchPkg"]
    for row_dict in list(vul_list):
        del_flag = 0
        sast_cur_row_tuple = (row_dict.get("Project"), row_dict.get("Branch"), row_dict.get("MatchPkg"))
        sast_key_counts = Counter(
            (d["Project"], d["Branch"], d["MatchPkg"]) for d in vul_list if "SAST" in d.get("ScanType"))
        sast_confirmation_row = (
            row_dict.get("Project"), row_dict.get("Branch"), row_dict.get("MatchPkg"), row_dict.get("ScanType"))
        if ("SAST" in row_dict.get("ScanType")):
            if (sast_key_counts[sast_cur_row_tuple] > 1):
                vul_list.remove(row_dict)
                del_flag = 1
            if (del_flag == 1):
                for sast_confirmation_indx, row in enumerate(vul_list):
                    if ("SAST" in row.get("ScanType") and
                            row.get("Project") == sast_confirmation_row[0] and
                            row.get("Branch") == sast_confirmation_row[1] and
                            row.get("MatchPkg") == sast_confirmation_row[2] and
                            row.get("ScanType") != sast_confirmation_row[3]):
                        vul_list[sast_confirmation_indx]['Msg'] = vul_list[sast_confirmation_indx][
                                                                      'Msg'] + f" \n !!!Confirmed by multiple tools!!!"

    # Remove duplicate Secrets findings.Group by["Project"], d["Branch"], d["MatchPkg"]
    for row_dict in list(vul_list):
        if ("Secrets" in row_dict.get("VulTechFamily")):
            secrets_cur_row_tuple = (row_dict.get("Project"), row_dict.get("Branch"), row_dict.get("MatchPkg"))
            del_flag = 0
            secrets_key_counts = Counter(
                (d["Project"], d["Branch"], d["MatchPkg"]) for d in vul_list if "Secrets" in d.get("VulTechFamily"))
            secrets_confirmation_cur_row = (
            row_dict.get("Project"), row_dict.get("Branch"), row_dict.get("MatchPkg"), row_dict.get("ScanType"))
            if (secrets_key_counts[secrets_cur_row_tuple] > 1):
                del_flag = 1
            if (del_flag == 1):
                vul_list.remove(row_dict)
                for secrets_confirmation_indx, row in enumerate(vul_list):
                    if ("Secrets" in row_dict.get("VulTechFamily") and
                            row.get("Project") == secrets_confirmation_cur_row[0] and
                            row.get("Branch") == secrets_confirmation_cur_row[1] and
                            row.get("MatchPkg") == secrets_confirmation_cur_row[2] and
                            row.get("ScanType") != secrets_confirmation_cur_row[3]):
                        vul_list[secrets_confirmation_indx]['Msg'] = vul_list[secrets_confirmation_indx][
                                                                         'Msg'] + f" \n !!!Confirmed by multiple tools!!!"

    return vul_list


def slack_group_severities_by_sast(vul_list):
    results_group_by_project = []
    slack_severity_list = []
    slack_msg = ""
    slack_severity_dict = {}
    sast_key_counts = ()
    severity_counts_str = ""
    sortedreader = sorted(vul_list, key=lambda d: (d['Project'], d['Severity']))
    groups = itertools.groupby(sortedreader, key=lambda d: (d['Project'], d['Severity']))
    result = [{'Project': list(key)} for key, values in groups]
    sast_key_counts = Counter((d["Project"], d["Severity"]) for d in vul_list if "SAST" in d.get("ScanType"))
    checked_prjs = []
    for k,v in sast_key_counts.items():
        next_prj = k[0]
        tmp_prj = ""
        slack_severity_dict ={next_prj:{k[1]:v}}
        slack_severity_list.append(slack_severity_dict)
    for row_dict in slack_severity_list:
        for cur_prj, severity_and_count in row_dict.items():
            tmp_str = ""
            if(checked_prjs is None or cur_prj not in checked_prjs):
                checked_prjs.append(cur_prj)                
                tmp_dict_list = [cur_dict for cur_dict in slack_severity_list if list(cur_dict.keys())[0] == cur_prj ]                
                for row_dict in tmp_dict_list:
                    proz = list(row_dict.keys())[0]
                    #tmp_str = ""
                    for tmp_prj,tmp_severity_and_count in row_dict.items():
                        tmp_dict = {cur_prj:{}}

                        for inner_sev,inner_count in tmp_severity_and_count.items():#{'MEDIUM': 11}                            
                            if(inner_sev in  ("HIGH","CRITICAL")):
                                tmp_str = tmp_str + f" *{inner_sev}*;{inner_count}\n>"
                            else:
                                tmp_str = tmp_str + f" {inner_sev};{inner_count}\n>"
                results_group_by_project.append({cur_prj:tmp_str})                
    return results_group_by_project

def slack_group_severities_by_sca(vul_list):
    results_group_by_project = []
    slack_severity_list = []
    slack_msg = ""
    slack_severity_dict = {}
    sast_key_counts = ()
    severity_counts_str = ""
    sortedreader = sorted(vul_list, key=lambda d: (d['Project'], d['Severity']))
    groups = itertools.groupby(sortedreader, key=lambda d: (d['Project'], d['Severity']))
    result = [{'Project': list(key)} for key, values in groups]
    sast_key_counts = Counter((d["Project"], d["Severity"]) for d in vul_list if "SCA" in d.get("ScanType"))
    checked_prjs = []
    for k,v in sast_key_counts.items():
        next_prj = k[0]
        tmp_prj = ""
        slack_severity_dict ={next_prj:{k[1]:v}}
        slack_severity_list.append(slack_severity_dict)
    for row_dict in slack_severity_list:
        for cur_prj, severity_and_count in row_dict.items():
            tmp_str = ""
            if(checked_prjs is None or cur_prj not in checked_prjs):
                checked_prjs.append(cur_prj)                
                tmp_dict_list = [cur_dict for cur_dict in slack_severity_list if list(cur_dict.keys())[0] == cur_prj ]
                for row_dict in tmp_dict_list:
                    proz = list(row_dict.keys())[0]
                    #tmp_str = ""
                    for tmp_prj,tmp_severity_and_count in row_dict.items():
                        for inner_sev,inner_count in tmp_severity_and_count.items():#{'MEDIUM': 11}                            
                            if (inner_sev in ("HIGH", "CRITICAL")):
                                tmp_str = tmp_str + f" *{inner_sev}*;{inner_count}\n>"
                            else:
                                tmp_str = tmp_str + f" {inner_sev};{inner_count}\n>"                        
                results_group_by_project.append({cur_prj:tmp_str})
                #print("----------------------")    
    return results_group_by_project


def push_s3_report_url_to_slack():
    report_url = f"https://s3.eu-central-1.amazonaws.com/reportpath/scans-{datetime.today().strftime('%Y-%m-%d')}_unified_scan_results.json"
    ntf_msg = f""

    slack_json_msg = {"text": "Appsec Scans Report",
                      "blocks": [
                          {
                              "type": "section",
                              "block_id": "section567",
                              "text": {
                                  "type": "mrkdwn",
                                  "text": f"Drilldown details  :male-detective: <{report_url}|Report Link>  \n"
                              }
                          }
                      ]
                      }    
    resp = requests.post(channel_webhook, json=slack_json_msg)
    return resp.text

def uniq(lst):
    mylist_unique = [{'Project': key} for key, values in itertools.groupby(lst, lambda dct: dct['Project'])]
    sortedreader = sorted(lst, key=lambda d: (d['Project'], d['ScanType']))
    groups = itertools.groupby(sortedreader, key=lambda d: (d['Project'], d['ScanType']))
    result = [{'Project': list(key)} for key, values in groups]    
    return result

def clean_string_for_jql_exp(raw_string):
    jql_blocked_chars = ["(", ")", "[", "]", "'", "`"]
    cleansed_str = raw_string.replace("/Parsing", "")  # Parser is a keyword for Jira and can not process it in jql
    txt_table = cleansed_str.maketrans('', '', ''.join(jql_blocked_chars))
    cleansed_str = cleansed_str.translate(txt_table)
    # url_encoded_str = urllib.parse.quote_plus(f"'{cleansed_str.translate(txt_table)}'")
    return cleansed_str

def read_unified_results_file(file_path):
    global dictData
    with open(file_path) as d:
        dictData = json.load(d)
    return dictData

# CVSV3Score is set either to NVD attr or ghsa attr, return immediately once whatever attr is set
def trivy_identify_cvss_score(cvss_dict):
    cvss_score = 0
    # vul.get("CVSS").get(existing_attr).get("V3Score") if vul.get("CVSS").get(existing_attr).get("V3Score") else vul.get("CVSS").get(existing_attr).get("V2Score")
    if (cvss_dict.get("nvd") is not None):
        if (cvss_dict.get("nvd").get("V3Score") is not None):
            cvss_score = cvss_dict.get("nvd").get("V3Score")
            return cvss_score
        else:
            cvss_score = cvss_dict.get("nvd").get("V2Score")
    if (cvss_dict.get("redhat") is not None):
        if (cvss_dict.get("redhat").get("V3Score") is not None):
            cvss_score = cvss_dict.get("redhat").get("V3Score")
            return cvss_score
    if (cvss_dict.get("ghsa") is not None):
        if (cvss_dict.get("ghsa").get("V3Score") is not None):
            cvss_score = cvss_dict.get("ghsa").get("V3Score")
            return cvss_score

    return cvss_score

def aggregate_results_to_push_on_slack(filtered_vul_list):
    # format is: C# findings: 8, js Findings:12, Secrets findings: 2    
    aggregated_results_dict_list = []
    vul_types = Counter(k['VulTechFamily'] for k in filtered_vul_list if k.get('VulTechFamily'))    
    for vul_type, count in vul_types.most_common():
        aggregated_results_dict = {vul_type: count}
        aggregated_results_dict_list.append(aggregated_results_dict)    
    return aggregated_results_dict_list


def detect_project_from_file_name(file_name):
    project = ""
    project = file_name[file_name.rfind('/') + 1:]
    project = project.split("_")[0]
    if (project not in sonar_project_list):
        sonar_project_list.append(project)
    return project


def get_branch_name():   
    return branch_name

def push_results_to_slack():
    result_list = read_unified_results_file(f"{scan_path}/unified_scan_results.json")
    sast_msg = build_slack_msg_by_severtiy_group("SAST", slack_group_severities_by_sast(result_list))
    sca_msg = build_slack_msg_by_severtiy_group("SCA", slack_group_severities_by_sca(result_list))
    push_vuln_report_to_slack(sast_msg)
    push_vuln_report_to_slack(sca_msg)    

    def put_reports_to_s3(s3_client, file_name_to_upload):    
    s3_client.Object(report_bucket_name,
                     f'path/scans-{datetime.today().strftime("%Y-%m-%d")}_{file_name_to_upload}').put(
        Body=open(f"{scan_path}/{file_name_to_upload}", 'rb'))
    response = s3_client.Object(report_bucket_name,
                                f'path/scans-{datetime.today().strftime("%Y-%m-%d")}.txt')


def is_secret_detected():    
    secret_filter_list = [item for item in results_to_relational_data_schema_dict_list if
                          item["VulTechFamily"] == "Secrets" and "N-A" not in item["Secret"]]
    return len(secret_filter_list) > 0

# region jira integration
def list_jira_ticket(jql_str):    
    issue_code = "key"
    body = "description"
    jira_dict = {}
    cvss = "customfield_10542"
    severity = "Severity"

    regression = "customfield_10521.get('value')"
    priority = "priority.get('Name')"
    components = "components.get('name')"
    headers = {'Content-Type': 'application/json'}
    jira_jql_results = jira_session.get(jql_str)
    sonuc_dict = json.loads(jira_jql_results.text)    
    return sonuc_dict

def check_is_jira_issue_duplicate(jql): 
    is_duplicate_jira_ticket = False
    jira_query_result = list_jira_ticket(jql)    
    ticket_Status = "xxx"    
    if (jira_query_result.get('issues')):  # if issues attr is [] then no data found for that jql        
        is_duplicate_jira_ticket = True
    return is_duplicate_jira_ticket


def jira_create_sast_ticket_format(scan_type,
                                   project_name,
                                   source_info,
                                   msg,
                                   lines,
                                   vultechFamily,
                                   cwe,
                                   severity,
                                   source_url):
    jira_sast_summary = ""
    jira_sast_body = ""
    # Summary-->Vulnerability: SAST/Semgrep raised an issue on projectName at fileName Body --> Message
    if ("Semgrep" in scan_type):
        jira_sast_body = f"{{panel:bgColor=#deebff}}\n\n{msg}\n\n*Lines*: {lines}\n\n*Vulnerable Tech*: {vultechFamily}\n*Cwe*:{cwe}\n*SourceUrl*: {source_url} {{panel}}\n🤖{{Created by AppSec Orchestrator Jira bot }}"
        jira_sast_summary = f"Vulnerability: SAST/Semgrep raised an issue on {project_name} {source_info}"
    if ("Snyk" in scan_type):
        jira_sast_body = f"{{panel:bgColor=#deebff}}\n\n{msg}\n\n*Lines*: {lines}\n\n*Vulnerable Tech*: {vultechFamily}\n*Cwe*:{cwe}\n*SourceUrl*: {source_url} {{panel}}\n🤖{{Created by AppSec Orchestrator Jira bot }}"
        jira_sast_summary = f"Vulnerability: SAST/Snyk raised an issue on {project_name} {source_info}"
    if ("Sonar" in scan_type):
        jira_sast_body = f"{{panel:bgColor=#deebff}}\n\n{msg}\n\n*Lines*: {lines}\n\n*Vulnerable Tech*: {vultechFamily}\n*Cwe*:{cwe}\n{{panel}}\n🤖{{Created by AppSec Orchestrator Jira bot }}"
        jira_sast_summary = f"Vulnerability: SAST/Sonarqube raised an issue on {project_name} {source_info}"

    return {"scanTool": {scan_type},
            "summary": jira_sast_summary,
            "description": jira_sast_body,
            "severity": severity,
            "CVSV3Score": 0.0,
            "sourceInfo": source_info,
            "lines": lines}


def jira_create_sca_ticket_format(scan_type,
                                  project_name,
                                  branch,
                                  pkg_name,
                                  artifactType,
                                  vulnerability_id,
                                  severity,
                                  cvsv3Score,
                                  installed_ver,
                                  fixed_ver,
                                  source_info,
                                  msg,
                                  vultechFamily,
                                  cveUrl,
                                  references,
                                  publishedDate,
                                  cwe):
    jira_sca_summary = ""
    jira_sca_body = ""
    sca_tool = ""
    sca_tool = scan_type[scan_type.index("-") + 1:]  # SCA-Whitesource

    jira_sca_summary = f"Vulnerability: SCA/{sca_tool} raised an issue on {project_name} {branch} at {pkg_name}"
    jira_sca_body = f"{{panel:bgColor=#deebff}}\n\n*ArtifactType*: {artifactType} \nDetected vulnerability at {source_info}\n\n *Branch*: {branch}\n *CVE*: {vulnerability_id} \n\n *InstalledVersion*: {installed_ver}\n\n \n\n *FixedVersion*: {fixed_ver}\n\n *Vulnerable Tech*: {vultechFamily}\n *CVE-Url*: {cveUrl}\n*PublishedDate*: {publishedDate}\n*Cwe*:{cwe}\n*References*: {references}{{panel}}\n\n*Message*:{msg}\n\n🤖{{Created by Platform Team Appsec Jira bot }}"
    return {"scanTool": scan_type,
            "summary": jira_sca_summary,
            "description": jira_sca_body,
            "sourceInfo": source_info,
            "pkg_name": pkg_name,
            "vulnerabilityId": vulnerability_id,
            "severity": severity,
            "cvsv3Score": cvsv3Score
            }


def create_jira_ticket_from_unified_results():
    jql_blocked_chars = ["(", ")", "[", "]", "'"]
    global src_base_url
    src_url = ""
    cur_date = str(dt.date.today())
    result_list = read_unified_results_file(f"{scan_path}/unified_scan_results.json")
    severity = ""    
    # f"Vulnerability:Triviy/SCA raised an issue on {project_name} at  {package_name}"
    for result_row in result_list:
        if ("SAST" in result_row.get("ScanType")):
            lineInfo = ","
            msg = clean_string_for_jql_exp(result_row.get('Msg'))
            project = clean_string_for_jql_exp(result_row.get('Project'))
            escaped_source_info = urllib.parse.quote_plus(f"'{result_row.get('SourceInfo')}'")
            # for proj,url in src_base_url_dict.items():
            #     base_url = src_base_url_dict[project]
            #     src_url = f"{base_url}{result_row.get('PackageName')}"            
            # return
            escaped_project = urllib.parse.quote_plus(f"'{project}'")
            escaped_message = urllib.parse.quote_plus(f"'{msg}'")
            lines_list = result_row.get('SourceLines')
            severity = result_row.get('Severity')
            severity = severity.capitalize()            
            lineInfo = ','.join(str(x) for x in lines_list)
            jql = f"{jira_api_base_url}/search?jql=project%3DINV%20AND%20(summary%20~%20{escaped_source_info}%20AND%20summary%20~%20{escaped_project})%20AND%20description%20~%20{escaped_message}"
            if (not check_is_jira_issue_duplicate(jql)):
                sast_ticket_dict = jira_create_sast_ticket_format(result_row.get("ScanType"),
                                                                  project, result_row.get('SourceInfo'),
                                                                  msg,
                                                                  lineInfo,
                                                                  result_row.get('VulTechFamily'),
                                                                  result_row.get('Cwe'),
                                                                  severity,
                                                                  src_base_url)
                jira_create_issue(sast_ticket_dict)

        if ("SCA" in result_row.get("ScanType")):
            cve = f"'{result_row.get('CVE')}'"
            trivy_severity = result_row.get('Severity')
            trivy_severity = trivy_severity.capitalize()
            cvsv3Score = 0.0 if (result_row.get('CVSV3Score') == "N-A") else result_row.get('CVSV3Score')
            cwe = f"{result_row.get('Cwe')}"
            escaped_source_info = urllib.parse.quote_plus(f"'{result_row.get('SourceInfo')}'")
            msg = clean_string_for_jql_exp(result_row.get('Msg'))
            project = clean_string_for_jql_exp(result_row.get('Project'))
            branch = clean_string_for_jql_exp(result_row.get('Branch'))
            escaped_project = urllib.parse.quote_plus(f"'{project}'")
            pkgName = clean_string_for_jql_exp(result_row.get('PackageName'))
            escaped_pkg_name = urllib.parse.quote_plus(f"'{pkgName}'")            
            sca_ticket_dict = jira_create_sca_ticket_format(result_row.get("ScanType"),
                                                            project,
                                                            branch,
                                                            pkgName,
                                                            result_row.get("ArtifactType"),  # docker img or filesystem
                                                            result_row.get('CVE'),
                                                            trivy_severity,
                                                            cvsv3Score,
                                                            result_row.get('InstalledVersion'),
                                                            result_row.get('FixedVersion'),
                                                            result_row.get('SourceInfo'),
                                                            msg,
                                                            result_row.get('VulTechFamily'),
                                                            result_row.get('VulnerabilityUrl'),
                                                            result_row.get('ReferenceUrl'),
                                                            result_row.get('PublishedDate'),
                                                            cwe)            
            # jql = f"{jira_api_base_url}/search?jql=project%3DSSDLC%20AND%20(summary%20~%20{escaped_project}%20AND%20summary%20~%20{escaped_pkg_name})%20AND%20description%20~%20{cve}"
            jql = f"{jira_api_base_url}/search?jql=project%3DINV%20AND%20(summary%20~%20{escaped_project}%20AND%20summary%20~%20{escaped_pkg_name})%20AND%20description%20~%20{cve}"
            if (not check_is_jira_issue_duplicate(jql)):
                jira_create_issue(sca_ticket_dict)

def jira_create_issue(ticket_dict):    
    # return
    auth = HTTPBasicAuth(jira_user, jira_token)
    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json"
    }
    # session.auth = (user, jira_token)
    url = "https://xxx.atlassian.net/rest/api/latest/issue"
    # sast_jira_description = f"{{panel:bgColor=#deebff}}\n\n{ticket_scheme_dict.get('description')}\n\n*Lines*: {ticket_scheme_dict.get('lines')}{{panel}}\n*Created by AppSec Orchestrator Jira bot*"
    payload = json.dumps({
        "update": {},
        "fields": {
            "summary": ticket_dict.get('summary'),
            "issuetype": {
                "id": "10007"
            },
            "components": [],
            "customfield_10161": {  # Severity
                "self": "https://xxx.atlassian.net/rest/api/2/customFieldOption/10332",
                "value": ticket_dict.get('severity'),
                "id": "10332"
            },
            "customfield_10542": ticket_dict.get("cvsv3Score"),  # CVSS3 score
            "customfield_10521": {"self": "https://xxx.atlassian.net/rest/api/2/customFieldOption/11381",
                                  "value": "Yes", "id": "11381"},
            # regression
            "project": {
                "self": "https://xxx.atlassian.net/rest/api/2/project/10108",
                "id": "10108",
                "key": "PrjKey",
                "name": "PrjName",
                "projectTypeKey": "software",
                "simplified": "false",
                "avatarUrls": {
                    "48x48": "https://xxx.atlassian.net/rest/api/2/universal_avatar/view/type/project/avatar/10627",
                    "24x24": "https://xxx.atlassian.net/rest/api/2/universal_avatar/view/type/project/avatar/10627?size=small",
                    "16x16": "https://xxx.atlassian.net/rest/api/2/universal_avatar/view/type/project/avatar/10627?size=xsmall",
                    "32x32": "https://xxx.atlassian.net/rest/api/2/universal_avatar/view/type/project/avatar/10627?size=medium"
                }
            },
            "description": ticket_dict.get('description'),
            "reporter": {
                "id": "repoertId"
            },
            "priority":
                {
                    "iconUrl": "https://xxx.atlassian.net/images/icons/priorities/high.svg",
                    "name": "High",
                    "id": "2"
                },
            "labels":
                [
                    "security-incident",
                    "app-sec"
                ],
            # "security": "",
            "environment": "",
            "versions": [],
            # "duedate": "",
            "assignee": {}
        }
    })

    response = requests.request(
        "POST",
        url,
        data=payload,
        headers=headers,
        auth=auth
    )
    


# endregion UtilFunctions

def trivy_traverse_json_4_vulns(trivy_json_result_2_parse, p_selected_severity_levels):
    global unique_record
    global dictData
    artifact_type = ""
    project = detect_project_from_file_name(trivy_json_result_2_parse)
    branch = get_branch_name()
    referenceUrls = "N-A"
    detail = ""
    vultechtype = ""
    cvss_score = "N-A"
    fixed_version = "N-A"
    cvss_score = "N-A"
    description = ""
    trivy_parsed_result_2_json_list = []
    with open(trivy_json_result_2_parse) as d:
        dictData = json.load(d)
    trivy_parsed_vulns_list = []
    artifact_type = dictData.get("ArtifactType")
    if (dictData.get("Results") is not None and any("Vulnerabilities" in d for d in dictData.get("Results"))):
        for indx, row in enumerate(dictData.get("Results")):
            trivy_vulns = row.get("Vulnerabilities")
            if (trivy_vulns is not None):
                vultechtype = row.get("Type")
                detail = row.get("Target")
                for vul in trivy_vulns:
                    severity = vul.get("Severity")
                    if (severity in p_selected_severity_levels):
                        triviy_parsed_result_2_json = {}
                        if (vul.get("CVSS")):  # CVSS keys might differ in docker scans
                            cvss_score = trivy_identify_cvss_score(vul.get('CVSS'))
                        if (vul.get("FixedVersion")):
                            fixed_version = vul.get("FixedVersion")
                        description = vul.get("Description") if len(vul.get("Description")) < 501 else vul.get(
                            "Description")[:500]
                        if (vul.get("References")):
                            referenceUrls = sca_aggregate_references(vul.get("References"))
                        pkg_to_match = drop_prj_name_from_pckg_name(vul.get("PkgName"))
                        triviy_parsed_result_2_json = {
                            "PackageName": vul.get("PkgName"),
                            "MatchPkg": pkg_to_match,
                            "ArtifactType": artifact_type,
                            "Details": detail,
                            "VulTech": vultechtype,
                            "VulnerabilityID": vul.get("VulnerabilityID"),
                            "VulnerabilityUrl": vul.get("PrimaryURL"),
                            "InstalledVersion": vul.get("InstalledVersion"),
                            "FixedVersion": fixed_version,
                            "Severity": vul.get("Severity"),
                            "CvssV3Score": cvss_score,
                            "Msg": description.strip(),
                            "Project": project,
                            "Branch": branch,
                            "Secret": "N-A",
                            "ReferenceUrl": referenceUrls,
                            "Cwe": vul.get("CweIDs")[0] if (vul.get("CweIDs") is not None) else "N-A",
                            "PublishedDate": "N-A" if (vul.get("PublishedDate") is None) else vul.get("PublishedDate")
                        }
                        trivy_parsed_vulns_list.append(triviy_parsed_result_2_json)
        return trivy_parsed_vulns_list
    else:
        return -1

def trivy_traverse_json_4_secrets(trivy_json_result_2_parse):
    global unique_record
    global dictData
    project = detect_project_from_file_name(trivy_json_result_2_parse)
    branch = get_branch_name()
    detail = ""
    vultechtype = ""
    cvss_score = "N-A"
    fixed_version = "N-A"
    description = ""
    secret_exposed = "N-A"
    trivy_secrets_exposed_list = []
    with open(trivy_json_result_2_parse) as d:
        dictData = json.load(d)
    trivy_parsed_vulns_list = []
    artifact_type = dictData.get("ArtifactType")
    if (dictData.get("Results") is not None):
        for indx, row in enumerate(dictData.get("Results")):            
            trivy_class = row.get("Class")
            if (trivy_class is not None and "secret" == trivy_class):
                trivy_secrets_list = row.get("Secrets")
                vultechtype = row.get("Category")
                detail = row.get("Target")
                pkg_to_match = drop_prj_name_from_pckg_name(detail)
                for secret in trivy_secrets_list:
                    triviy_parsed_result_2_json = {}
                    if (secret.get("Match")):
                        secret_exposed = secret.get("Match")
                    if (secret.get("CVSS")):
                        cvss_score = secret.get("CVSS").get("nvd").get("V3Score")
                    if (secret.get("FixedVersion")):
                        fixed_version = secret.get("FixedVersion")
                    severity = secret.get("Severity")
                    description = f"Found {secret.get('Category')} secret at {detail}"
                    triviy_parsed_result_2_json = {
                        "PackageName": detail,
                        "MatchPkg": pkg_to_match,
                        "ArtifactType": artifact_type,
                        "Details": f"{vultechtype} {detail}",
                        "VulTech": "Secrets",
                        "VulnerabilityID": "N-A",
                        "VulnerabilityUrl": "N-A",
                        "InstalledVersion": "N-A",
                        "FixedVersion": fixed_version,
                        "ReferenceUrl": "N-A",
                        "PublishedDate": "N-A",
                        "Cwe": "N-A",
                        "Severity": secret.get("Severity"),
                        "CvssV3Score": cvss_score,
                        "Msg": description.strip(),
                        "Project": project,
                        "Branch": branch,
                        "Secret": secret_exposed}

                    trivy_secrets_exposed_list.append(triviy_parsed_result_2_json)
        return trivy_secrets_exposed_list
    else:
        return -1

def scan_secrets_yelp(yelp_json_result_2_parse):
    global unique_record
    global dictData
    project = detect_project_from_file_name(yelp_json_result_2_parse)
    branch = get_branch_name()
    detail = ""
    vultechtype = ""
    cvss_score = "N-A"
    fixed_version = "N-A"
    description = ""
    secret_exposed = "N-A"
    yelp_secrets_exposed_list = []
    with open(yelp_json_result_2_parse) as d:
        dictData = json.load(d)
    artifact_type = "N-A"
    if (dictData.get("results") is not None):
        for k, v in dictData.get("results").items():
            lines = []
            description = ""
            flag = 0
            for dict_row in v:
                file_type = detect_vul_tech_type(dict_row.get('filename'), "yelp")
                # filter records with less FPs
                if (file_type == "C#" or ("Entropy" not in dict_row.get("type") and file_type != "C#" and dict_row.get(
                        "line_number") not in lines)):
                    flag = 1
                    lines.append(dict_row.get("line_number"))
                    description = f"Found {dict_row.get('type')} secret at {dict_row.get('filename')}"
            if (flag == 1):
                yelp_parsed_result_2_json = {
                    "PackageName": k,
                    "MatchPkg": drop_prj_name_from_pckg_name(k),
                    "ArtifactType": artifact_type,
                    "Details": f"{k}",
                    "VulTech": "Secrets",
                    "Lines": lines,
                    "VulnerabilityID": "N-A",
                    "VulnerabilityUrl": "N-A",
                    "InstalledVersion": "N-A",
                    "FixedVersion": fixed_version,
                    "ReferenceUrl": "N-A",
                    "PublishedDate": "N-A",
                    "Cwe": "N-A",
                    "Severity": "HIGH",
                    "CvssV3Score": cvss_score,
                    "Msg": description.strip(),
                    "Project": project,
                    "Branch": branch,
                    "Secret": secret_exposed}
                yelp_secrets_exposed_list.append(yelp_parsed_result_2_json)
        return yelp_secrets_exposed_list
    else:
        return -1

def trivy_orig_parse_json_results(trivy_json_result_2_parse, p_selected_severity_levels):
    '''
      1. Search trivy json for vulns
      2. Search trivy json for secrets
      3.Concat two trivy lists to return
    '''
    trivy_vulns_list = trivy_traverse_json_4_vulns(trivy_json_result_2_parse, p_selected_severity_levels)
    trivy_secrets_list = trivy_traverse_json_4_secrets(trivy_json_result_2_parse)
    if (trivy_vulns_list != -1 and trivy_secrets_list != -1):
        trivy_final_list = trivy_vulns_list + trivy_secrets_list
        return trivy_final_list
    if (trivy_vulns_list != -1):
        return trivy_vulns_list
    if (trivy_secrets_list != -1):
        return trivy_secrets_list
    return -1


def detect_vul_tech_type(source_file, err_msg):
    sast_vul_type = "N/A"
    secrets_list = ["AWS Access Key", "AWS Session Token", "OAuth", "Username and password", "Secret", "s3Secret"]
    csharp_list = ["cshtml", "cs"]
    java_list = ["java", "jsf", "jsp"]
    integrity_vul_list = ["integrity", "Integrity"]
    debug_dump_list = ["debug template"]
    insecure_socket_list = ["Insecure WebSocket"]
    js_list = ["innerHTML", "outerHTML", "XSS", "document.write"]
    if (source_file and (
            source_file.endswith((".cshtml", ".cs")) or any(csharp_code in err_msg for csharp_code in csharp_list))):
        sast_vul_type = "C#"
    if (source_file and (
            source_file.endswith((".java")) or any(java_code in err_msg for java_code in java_list))):
        sast_vul_type = "Java"
    if (source_file and (
            source_file.endswith((".js", ".vue", ".knockout")) or any(jscode in err_msg for jscode in js_list))):
        sast_vul_type = "js"
    if (source_file and source_file.endswith(".php")):
        sast_vul_type = "Php"
    if (source_file and (any(secret in source_file for secret in secrets_list) or any(
            secret_in_line in err_msg for secret_in_line in secrets_list))):
        sast_vul_type = "Secrets"
    if (source_file and (any(integrity_msg in source_file for integrity_msg in integrity_vul_list) or any(
            integrity_msg in err_msg for integrity_msg in integrity_vul_list))):
        sast_vul_type = "Integrity"
    if (source_file and (any(debug_tmp_msg in source_file for debug_tmp_msg in debug_dump_list) or any(
            debug_tmp_msg in err_msg for debug_tmp_msg in debug_dump_list))):
        sast_vul_type = "DebugDumpToClient"
    if (source_file and (any(insecure_socket_msg in source_file for insecure_socket_msg in insecure_socket_list) or any(
            insecure_socket_msg in err_msg for insecure_socket_msg in insecure_socket_list))):
        sast_vul_type = "Insecure-Websocket"
    return sast_vul_type

'''
builds a string with pkg name and its count like {'follow-redirects': 6}, {'node-forge': 6}, {'url-parse': 6}, {'tar': 5}, {'RazorEngine': 3}
'''
def parse_semgrep_results(semgrep_json_result_file, p_filtered_severity_levels):
    semgrep_vulns = []
    project = detect_project_from_file_name(semgrep_json_result_file)
    branch = get_branch_name()
    cwe = "N-A"
    semgrep_vul_severity = ""
    semgrep_detected_source_file = ""
    semgrep_detected_source_line = ""
    semgrep_detected_source_file_and_line = ""
    semgrep_detected_line = ""
    semgrep_vul_type = "N-A"  # is it a secret vul,lang vul etc
    semgrep_err_msg = ""
    secrets_list = ["AWS Access Key", "AWS Session Token", "OAuth", "Username and password"]
    secret_value = ""
    semgrep_parsed_result_dict = {}

    with open(semgrep_json_result_file) as d:
        dictData = json.load(d)
        
    for indx, row in enumerate(dictData.get("results")):
        cwe = "N-A"
        pkg_name = "N-A"
        semgrep_vul_severity = ""
        semgrep_detected_source_file = ""
        semgrep_detected_source_line = ""
        semgrep_detected_source_file_and_line = ""
        semgrep_detected_line = ""
        semgrep_vul_type = "N-A"  # is it a secret vul,lang vul etc
        semgrep_err_msg = ""
        secret_value = ""
        if (isinstance(row, dict) and (row.get("extra").get("metadata").get("category") == "security" and
                                       not any(exc_lib in row.get("path") for exc_lib in sast_excluded_libs))):
            semgrep_detected_source_file = row.get("path")
            pkg_name = semgrep_detected_source_file
            pkg_name_to_match = drop_prj_name_from_pckg_name(pkg_name)
            semgrep_err_msg = row.get("extra").get("message")
            semgrep_err_msg = semgrep_err_msg.replace("`", "")
            # pass tupple to check against list of possible file types
            semgrep_vul_type = detect_vul_tech_type(semgrep_detected_source_file, semgrep_err_msg.strip())
            secret_value_raw = row.get("extra").get("lines")
            secret_value = secret_value_raw.strip()
            if (semgrep_vul_type == "Secrets" and (not "OAuth" in semgrep_err_msg)):
                secret_value = secret_value_raw
                secret_value = hashlib.sha256(secret_value.encode('utf-8')).hexdigest()
            else:
                secret_value = "N-A"
            semgrep_vul_severity = row.get("extra").get("severity") if row.get("extra").get("metadata").get(
                "confidence") is None else row.get("extra").get("metadata").get("confidence")
            if (semgrep_vul_severity in p_filtered_severity_levels):
                cwe = row.get("extra").get("metadata").get("cwe") if (
                        row.get("extra").get("metadata").get("cwe") is not None) else cwe                
                semgrep_detected_source_line = row.get('start').get('line')
                semgrep_detected_source_file_and_line = f"At: {semgrep_detected_source_file}"
                semgrep_parsed_result_dict = {"VulTechFamily": semgrep_vul_type,
                                              "PackageName": pkg_name,
                                              "MatchPkg": pkg_name_to_match,
                                              "ErrorMsg": semgrep_err_msg,
                                              "Severity": semgrep_vul_severity,
                                              "Details": semgrep_detected_source_file_and_line,
                                              "SecretValue": secret_value.strip(),
                                              "Line": semgrep_detected_source_line,
                                              "Project": project,
                                              "Branch": branch,
                                              "Cwe": cwe}
                if ("vue-2.6.8.js" in semgrep_detected_source_file):
                    pass                    
                semgrep_vulns.append(semgrep_parsed_result_dict)
                semgrep_vul_type = "N-A"
                secret_value = "N-A"    
    return semgrep_vulns


# transform duplicate libs to a single lib and unify line numbers in a single 'Lines' attr
def sast_wrap_lines_with_respective_libs(sast_parsed_list):
    wrapped_list = []
    sorted_unique_list = []
    wrapped_list = list({v['Details']: v for v in sast_parsed_list}.values())  # remove dups
    # region create a dict value as a list of detected source code lines where the related lib is the key attr
    temp_dict_to_pivot_lines = {}
    for d in sast_parsed_list:
        temp_dict_to_pivot_lines.setdefault(d['Details'], []).append(d['Line'])
        # sort found line numbers
    for k, v in temp_dict_to_pivot_lines.items():  # v is 'Lines' list
        unique_list = list(set(v))
        temp_dict_to_pivot_lines[k] = sorted(unique_list)    
    for row in wrapped_list:
        row.pop('Line', 'None')  # Line attr is no more needed since all lines are aggregated in 'Lines' attr
        #get unique lines from dict "temp_dict_to_pivot_lines"
        row['Lines'] = temp_dict_to_pivot_lines.get(row.get("Details"))
    # wrapped_list = json.dumps(wrapped_list)    
    return wrapped_list


def mend_build_final_results_for_global_sca(p_mend_projects, p_selected_severity_levels):
    mend_vulns = []    
    for item in p_mend_projects:
        vulns_by_projects = mend_get_vulns_by_projects(item.get("projectToken"))
        if(vulns_by_projects):
            for vul_row in vulns_by_projects:
                if (vul_row):
                    mend_vulns = mend_parse_api_results(p_selected_severity_levels, vulns_by_projects)
                    if (mend_vulns):
                        create_sca_unified_scan_results(mend_vulns, "Whitesource")

    # mend_api_list = whitesource_parse_api_results(p_selected_severity_levels, "main")
    # if (mend_api_list):
    #     mend_scan_result = create_sca_unified_scan_results(mend_api_list, "Whitesource")

def sca_group_libs_by_highest_cve(sca_parsed_list):
    max_CvssV3Score = 0
    del_flag = 0
    sca_confirmation_tuple = ()        
    # Remove duplicate SCA findings, group by Project,Branch,CVE
    for row_dict in list(sca_parsed_list):
        cur_cvssV3Score_list = []
        dup_issues_dict = {}
        sca_dup_counts = Counter((d["Project"], d["Branch"], d["MatchPkg"])
                                 for d in sca_parsed_list if d.get("VulnerabilityID") not in ("N-A", "None") and
                                 d.get("CvssV3Score") not in ("N-A", 0, "None"))
        del_flag = 0        
        sca_cur_row_tuple = (row_dict.get("Project"),
                             row_dict.get("Branch"),
                             row_dict.get("MatchPkg"))
        if (row_dict.get("VulnerabilityID") not in ("N-A", "None") and sca_dup_counts[sca_cur_row_tuple] > 1):            
            del_flag = 1
            # select rows where project,branch and Matchpkg in join
            dup_sca_findings = [item for item in sca_parsed_list
                                if item.get("Project") == row_dict.get("Project") and
                                item.get("Branch") == row_dict.get("Branch") and
                                item.get("MatchPkg") == row_dict.get("MatchPkg")]
            # Get CvssV3Score for the current lib
            try:
                for row in dup_sca_findings:
                    if ( row.get("CvssV3Score") not in cur_cvssV3Score_list or 1 == 1):
                        cur_cvssV3Score_list.append(row.get("CvssV3Score"))
                # Find max CVSS3 score for the current lib
                indice, max_CvssV3Score = max(enumerate(cur_cvssV3Score_list), key=operator.itemgetter(1))
                if (max_CvssV3Score != 0):
                    # Get CVE of the highest CvssV3Score
                    highest_row_cve = next(
                        highest_scored_row.get("VulnerabilityID") for highest_scored_row in dup_sca_findings if
                        highest_scored_row.get("CvssV3Score") == max_CvssV3Score)
                    # Get Severity of the highest CvssV3Score
                    highest_row_severity = next(
                        highest_scored_row.get("Severity") for highest_scored_row in dup_sca_findings if
                        highest_scored_row.get("CvssV3Score") == max_CvssV3Score)
                    # Get FixedLib of the highest CvssV3Score
                    highest_row_fixed_version = next(
                        highest_scored_row.get("FixedVersion") for highest_scored_row in dup_sca_findings if
                        highest_scored_row.get("CvssV3Score") == max_CvssV3Score)
                dup_issues_dict = {row_dict.get("MatchPkg"): {"max_CvssV3Score": max_CvssV3Score,
                                                              "Project": row_dict.get("Project"),
                                                              "Severity": highest_row_severity,
                                                              "Branch": row_dict.get("Branch"),
                                                              "VulnerabilityID": highest_row_cve,
                                                              "FixedVersion": highest_row_fixed_version} }
                if (del_flag == 1):
                    sca_parsed_list.remove(row_dict)
                    for inx, row in enumerate(sca_parsed_list):
                        if (row.get("Project") == sca_cur_row_tuple[0] and
                                row.get("Branch") == sca_cur_row_tuple[1] and
                                row.get("MatchPkg") == sca_cur_row_tuple[2]):
                            sca_parsed_list[inx]['CvssV3Score'] = max_CvssV3Score
                            sca_parsed_list[inx]['Severity'] = dup_issues_dict.get(sca_cur_row_tuple[2]).get("Severity")
                            sca_parsed_list[inx]['VulnerabilityID'] = dup_issues_dict.get(sca_cur_row_tuple[2]).get(
                                "VulnerabilityID")
                            sca_parsed_list[inx]['FixedVersion'] = dup_issues_dict.get(sca_cur_row_tuple[2]).get(
                                "FixedVersion")
            except:
                print(row.get("CvssV3Score"))
                    
    return sca_parsed_list

def snyk_sast_aggregate_lines_of_same_file(snyk_parsed_list):
    wrapped_list = []
    sorted_unique_list = []
    wrapped_list = list({v['Details']: v for v in snyk_parsed_list}.values())  # remove dups
    # region create a dict value as a list of detected source code lines where the related lib is the key attr
    c = {}
    for d in snyk_parsed_list:
        c.setdefault(d['Details'], []).append(d['Line'])
        # sort found line numbers
    for k, v in c.items():  # v is 'Lines' list
        unique_list = list(set(v))
        c[k] = sorted(unique_list)    
    for row in wrapped_list:
        row.pop('Line', 'None')  # Line attr is no more needed since all lines are aggregated in 'Lines' attr
        row['Lines'] = c.get(row.get("Details"))
    # wrapped_list = json.dumps(wrapped_list)    
    return wrapped_list


def parse_snyk_sast_results(snyk_sast_json_result_file, p_filtered_severity_levels):    
    snyk_sast_vulns = []
    project = detect_project_from_file_name(snyk_sast_json_result_file)
    branch = get_branch_name()
    cwe = "N-A"
    snyk_sast_vul_severity = ""
    snyk_sast_detected_source_file = ""
    snyk_sast_detected_source_line = ""
    snyk_sast_detected_source_file_and_line = ""
    snyk_sast_detected_line = ""
    snyk_sast_vul_type = "N-A"  # is it a secret vul,lang vul etc
    snyk_sast_err_msg = ""
    secrets_list = ["AWS Access Key", "AWS Session Token", "OAuth", "Username and password"]
    secret_value = ""
    snyk_sast_parsed_result_dict = {}

    with open(snyk_sast_json_result_file) as d:
        dictData = json.load(d)    
    for indx, row in enumerate(dictData.get("runs")[0].get("results")):
        cwe = "N-A"
        snyk_sast_vul_severity = ""
        snyk_sast_detected_source_file = ""
        snyk_sast_detected_source_line = ""
        snyk_sast_detected_source_file_and_line = ""
        snyk_sast_detected_line = ""
        snyk_sast_vul_type = "N-A"  # is it a secret vul,lang vul etc
        snyk_sast_err_msg = ""
        secret_value = ""
        if (not any(exc_lib in row.get("locations")[0].get("physicalLocation").get("artifactLocation").get("uri") for
                    exc_lib in sast_excluded_libs)):
            snyk_sast_detected_source_file = row.get("locations")[0].get("physicalLocation").get(
                "artifactLocation").get("uri")
            pkg_name_to_match = drop_prj_name_from_pckg_name(snyk_sast_detected_source_file)
            snyk_sast_err_msg = row.get("message").get("text").replace("(BETA Suggestion)", "").strip() if row.get(
                "message").get("text") is not None else "N-A"
            # snyk_sast_err_msg = row.get("message").get("text")
            # pass tupple to check against list of possible file types
            snyk_sast_vul_type = detect_vul_tech_type(snyk_sast_detected_source_file, snyk_sast_err_msg)
            secret_value = "N-A"
            snyk_sast_vul_severity = row.get("level")            
            snyk_sast_detected_source_line = row.get('locations')[0].get("physicalLocation").get("region").get(
                "startLine")
            snyk_sast_detected_source_file_and_line = f"At: {snyk_sast_detected_source_file}"
            snyk_sast_parsed_result_dict = {"VulTechFamily": snyk_sast_vul_type, "ErrorMsg": snyk_sast_err_msg,
                                            "Severity": snyk_sast_vul_severity.upper(),
                                            "Details": snyk_sast_detected_source_file_and_line,
                                            "PackageName": snyk_sast_detected_source_file,
                                            "MatchPkg": pkg_name_to_match,
                                            "SecretValue": secret_value.strip(),
                                            "Line": snyk_sast_detected_source_line,
                                            "Project": project,
                                            "Branch": branch,
                                            "Cwe": cwe}
            snyk_sast_vulns.append(snyk_sast_parsed_result_dict)
            snyk_sast_vul_type = "N-A"
            secret_value = "N-A"    
    return snyk_sast_vulns


def sca_aggregate_references(ref_list):
    if (not ref_list):
        return "N-A"
    if (type(ref_list) == "List"):
        references_str = ""
        references_str = "\n".join(ref_list)
        return references_str

    return ref_list


def trivy_send_slack_notifications(trivy_vul_list):
    ntf_msg = ""    
    result = uniq(trivy_vul_list)
    report_url = f"https://s3.eu-central-1.amazonaws.com/path/scans-{datetime.today().strftime('%Y-%m-%d')}_unified_scan_results.json"
    scan_tool = "N-A"
    # ntf_msg = ntf_msg + "**************************** \n"
    if (channel_webhook):       
        for dict_row in result:
            ntf_flag = 0
            filter_predicates = [item for item in trivy_vul_list if item["Project"] == dict_row.get('Project')[0]]
            meta_data = select_from_list_of_dicts(filter_predicates, "VulTechFamily", "Project", "ScanType")            
            aggregated_sum_info_list = aggregate_results_to_push_on_slack(meta_data)            
            scan_tool = dict_row.get('Project')[1]
            ntf_msg = f"*{scan_tool} detected at {dict_row.get('Project')[0]} project*"            
            for aggr_dict_row in aggregated_sum_info_list:                
                for k, v in aggr_dict_row.items():
                    ntf_msg = ntf_msg + " \n"
                    ntf_msg = ntf_msg + f" {v} security findings on {k},  \n"
                    ntf_msg = ntf_msg.strip()
            
            slack_json_msg = {"text": "Trivy SCA Alerts",
                              "blocks": [
                                  {
                                      "type": "section",
                                      "block_id": "section567",
                                      "text": {
                                          "type": "mrkdwn",
                                          "text": f"{ntf_msg}  \n :fire:"
                                      }
                                  }
                              ]
                              }            
            resp = requests.post(channel_webhook, json=slack_json_msg)
        return resp.text


def build_slack_msg_by_severtiy_group(scan_type,grouped_vul_list):
    slc_msg = f"*{scan_type}* Results:\n"
    for row_dict in grouped_vul_list:
        for cur_prj,sev_and_cnt in row_dict.items():
            slc_msg = slc_msg + f"\n>Project: *{cur_prj}* \n>{sev_and_cnt}"
            slc_msg = slc_msg +"\n ---------------"    
    return slc_msg


def push_vuln_report_to_slack(ntf_msg):
    slack_json_msg = {"text": "Semgrep Secrets/SourceCode Alerts",
                      "blocks": [
                          {
                              "type": "section",
                              "block_id": "section567",
                              "text": {
                                  "type": "mrkdwn",
                                  "text": f"{ntf_msg}  \n :fire:"
                              }
                          }
                      ]
                      }    
    resp = requests.post(channel_webhook, json=slack_json_msg)

def sast_send_slack_notifications(sast_vul_list):
    ntf_msg = ""
    resp = ""    
    report_url = f"https://s3.eu-central-1.amazonaws.com/s3path/scans-{datetime.today().strftime('%Y-%m-%d')}_unified_scan_results.json"
    scan_tool = "N-A"

    if (channel_webhook):        
            slack_json_msg = {"text": "Semgrep Secrets/SourceCode Alerts",
                              "blocks": [
                                  {
                                      "type": "section",
                                      "block_id": "section567",
                                      "text": {
                                          "type": "mrkdwn",
                                          "text": f"{ntf_msg}  \n :fire:"
                                      }
                                  }
                                ]
                              }
# endregion

def create_sast_unified_scan_results(sast_scan_list, sast_tool):    
    global results_to_relational_data_schema_dict_list
    cur_date_in_dt_format = datetime.utcnow().isoformat()
    for sast_findings_row in sast_scan_list:
        if (results_to_relational_data_schema_dict_list
            and sast_findings_row.get("ScanType") is not None
            and sast_tool == "Sonarqube"):
            results_to_relational_data_schema_dict_list = results_to_relational_data_schema_dict_list + sast_scan_list
        if (sast_tool == "Semgrep"):
            semgrep_results_to_relational_data_schema_dict = {"ScanType": "SAST-Semgrep",
                                                              "Project": sast_findings_row.get("Project"),
                                                              "Branch": sast_findings_row.get("Branch"),
                                                              "PackageName": sast_findings_row.get("PackageName"),
                                                              "MatchPkg": sast_findings_row.get("MatchPkg"),
                                                              "Msg": sast_findings_row.get("ErrorMsg"),
                                                              "VulTechFamily": sast_findings_row.get("VulTechFamily"),
                                                              "CVE": "N-A",
                                                              "CVSV3Score": "0.0",
                                                              "Severity": sast_findings_row.get("Severity"),
                                                              "SourceInfo": sast_findings_row.get("Details"),
                                                              "Secret": sast_findings_row.get("SecretValue"),
                                                              "SourceLines": sast_findings_row.get("Lines"),
                                                              "InstalledVersion": "N-A",
                                                              "FixedVersion": "N-A",
                                                              "Cwe": sast_findings_row.get("Cwe"),
                                                              "ScanDateTimeUtc": cur_date_in_dt_format
                                                              }
            results_to_relational_data_schema_dict_list.append(semgrep_results_to_relational_data_schema_dict)

        if (sast_tool == "Snyk"):
            snyk_sast_results_to_relational_data_schema_dict = {"ScanType": "SAST-Snyk",
                                                                "Project": sast_findings_row.get("Project"),
                                                                "Branch": sast_findings_row.get("Branch"),
                                                                "PackageName": sast_findings_row.get("PackageName"),
                                                                "MatchPkg": sast_findings_row.get("MatchPkg"),
                                                                "Msg": sast_findings_row.get("ErrorMsg"),
                                                                "VulTechFamily": sast_findings_row.get("VulTechFamily"),
                                                                "CVE": "N-A",
                                                                "CVSV3Score": "0.0",
                                                                "Severity": sast_findings_row.get("Severity"),
                                                                "SourceInfo": sast_findings_row.get("Details"),
                                                                "Secret": sast_findings_row.get("SecretValue"),
                                                                "SourceLines": sast_findings_row.get("Lines"),
                                                                "InstalledVersion": "N-A",
                                                                "FixedVersion": "N-A",
                                                                "Cwe": sast_findings_row.get("Cwe"),
                                                                "ScanDateTimeUtc": cur_date_in_dt_format
                                                                }
            results_to_relational_data_schema_dict_list.append(snyk_sast_results_to_relational_data_schema_dict)
    return results_to_relational_data_schema_dict_list


def create_sca_unified_scan_results(sca_scan_list, sca_tool):    
    global results_to_relational_data_schema_dict_list
    cur_date_in_dt_format = datetime.utcnow().isoformat()
    if (sca_scan_list and sca_tool == "Whitesource"):
        if (results_to_relational_data_schema_dict_list):
            results_to_relational_data_schema_dict_list = results_to_relational_data_schema_dict_list + sca_scan_list

    if (sca_tool == "Trivy"):
        for sca_findings_row in sca_scan_list:
            trivy_results_to_relational_data_schema_dict = {"ScanType": "SCA-Trivy",
                                                            "Project": sca_findings_row.get("Project"),
                                                            "Branch": sca_findings_row.get("Branch"),
                                                            "PackageName": sca_findings_row.get("PackageName"),
                                                            "MatchPkg": sca_findings_row.get("MatchPkg"),
                                                            "ArtifactType": sca_findings_row.get('ArtifactType'),
                                                            "Msg": sca_findings_row.get("Msg"),
                                                            "VulTechFamily": sca_findings_row.get("VulTech"),
                                                            "CVE": sca_findings_row.get("VulnerabilityID"),
                                                            "VulnerabilityUrl": sca_findings_row.get(
                                                                "VulnerabilityUrl"),
                                                            "CVSV3Score": sca_findings_row.get("CvssV3Score"),
                                                            "Severity": sca_findings_row.get("Severity"),
                                                            "SourceInfo": sca_findings_row.get("Details"),
                                                            "Secret": sca_findings_row.get("Secret"),
                                                            "SourceLines": "N-A",
                                                            "InstalledVersion": sca_findings_row.get(
                                                                "InstalledVersion"),
                                                            "FixedVersion": sca_findings_row.get("FixedVersion"),
                                                            "ReferenceUrl": sca_findings_row.get("ReferenceUrl"),
                                                            "PublishedDate": sca_findings_row.get("PublishedDate"),
                                                            "Cwe": sca_findings_row.get("Cwe"),
                                                            "ScanDateTimeUtc": cur_date_in_dt_format
                                                            }
            results_to_relational_data_schema_dict_list.append(trivy_results_to_relational_data_schema_dict)
    if (sca_tool == "Yelp"):
        for sca_findings_row in sca_scan_list:
            yelp_results_to_relational_data_schema_dict = {"ScanType": "SCA-Yelp",
                                                           "Project": sca_findings_row.get("Project"),
                                                           "Branch": sca_findings_row.get("Branch"),
                                                           "PackageName": sca_findings_row.get("PackageName"),
                                                           "MatchPkg": sca_findings_row.get("MatchPkg"),
                                                           "ArtifactType": sca_findings_row.get('ArtifactType'),
                                                           "Msg": sca_findings_row.get("Msg"),
                                                           "VulTechFamily": sca_findings_row.get("VulTech"),
                                                           "CVE": sca_findings_row.get("VulnerabilityID"),
                                                           "VulnerabilityUrl": sca_findings_row.get(
                                                               "VulnerabilityUrl"),
                                                           "CVSV3Score": sca_findings_row.get("CvssV3Score"),
                                                           "Severity": sca_findings_row.get("Severity"),
                                                           "SourceInfo": sca_findings_row.get("Details"),
                                                           "Secret": sca_findings_row.get("Secret"),
                                                           "SourceLines": sca_findings_row.get("Lines"),
                                                           "InstalledVersion": sca_findings_row.get(
                                                               "InstalledVersion"),
                                                           "FixedVersion": sca_findings_row.get("FixedVersion"),
                                                           "ReferenceUrl": sca_findings_row.get("ReferenceUrl"),
                                                           "PublishedDate": sca_findings_row.get("PublishedDate"),
                                                           "Cwe": sca_findings_row.get("Cwe"),
                                                           "ScanDateTimeUtc": cur_date_in_dt_format
                                                           }
            results_to_relational_data_schema_dict_list.append(yelp_results_to_relational_data_schema_dict)

    return results_to_relational_data_schema_dict_list


# return response

def run_sca_scans(p_selected_severity_levels):    
    mend_build_final_results_for_global_sca(get_all_mend_projects(), p_selected_severity_levels)

    for file_name in get_files_under_curdir():
        if not any(exc_tool in file_name for exc_tool in exluded_tools):
            file_exists = os.path.exists(file_name)
            # check if scan result files are placed into proper path
            if (file_exists and check_file_size(file_name) != 0):
                if ("trivy" in file_name):
                    trivy_parsed_results = trivy_orig_parse_json_results(file_name, p_selected_severity_levels)
                    if (trivy_parsed_results != -1 and trivy_parsed_results):
                        sca_groupby_cve_list = sca_group_libs_by_highest_cve(trivy_parsed_results)
                        create_sca_unified_scan_results(sca_groupby_cve_list, "Trivy")
                if ("secrets_results" in file_name):
                    secrets_result = scan_secrets_yelp(file_name)                    
                    create_sca_unified_scan_results(secrets_result, "Yelp")
    return "success"


def run_sast_scans(p_filtered_severity_levels):
    global branch_name
    for file_name in get_files_under_curdir():
        if not any(exc_tool in file_name for exc_tool in exluded_tools):
            if (check_file_size(file_name) != 0):  # check if scan result files are placed into proper path
                if ("semgrep" in file_name):                    
                    semgrep_scan_result_wrapped = sast_wrap_lines_with_respective_libs(
                        parse_semgrep_results(file_name, p_filtered_severity_levels))
                    semgrep_scan_result = create_sast_unified_scan_results(semgrep_scan_result_wrapped, "Semgrep")
                if ("snyk_sast" in file_name):
                    snyk_sast_scan_result_wrapped = snyk_sast_aggregate_lines_of_same_file(
                        parse_snyk_sast_results(file_name, p_filtered_severity_levels))
                    create_sast_unified_scan_results(snyk_sast_scan_result_wrapped, "Snyk")
    for prj in sonar_project_list:
        if("acx" in prj or "acunetix" in prj or 1==1):
            sonar_api_list = sonar_parse_api_results(prj)
            if (sonar_api_list):
                sonar_scan_result = create_sast_unified_scan_results( sast_wrap_lines_with_respective_libs(sonar_api_list), "Sonarqube")
    return "success"


def sonar_api_integration(project, branch_name):   
    sonar_api_response = []    
    sonar_base64_token = base64.b64encode(bytes(f'{sonar_token}:', 'utf-8')).decode("ascii")
    sonar_headers = {'Authorization': 'Basic %s' % sonar_base64_token}
    try:
        sonar_sec_issues = requests.get(
            f"https://sonarqube.xxx.com/api/issues/search?componentKeys={project}&branch={branch_name}&types=VULNERABILITY",
            headers=sonar_headers)
        sonar_api_response = json.loads(sonar_sec_issues.text).get('issues')        
        return sonar_api_response
    except Exception as e:
        return sonar_api_response

def mend_api_get_project_tokens(product_token):
    # API Note: Only POST requests are accepted.
    mend_product_payload = {
        "requestType": "getAllProjects",
        "userKey": mend_userkey,
        "productToken": product_token
    }
    try:
        mend_response = requests.post(f"{mend_api_url}", data=json.dumps(mend_product_payload), headers=headers)
        mend_response_json = json.loads(mend_response.text)
        sonuc = mend_response.text
        sonuc = json.loads(sonuc)
        return sonuc.get("projects")
    except Exception as e:
        return str(e)

def get_mend_products():
    mend_product_payload = {
        "requestType": "getAllProducts",
        "userKey": mend_userkey,
        "orgToken": mend_org_token
    }
    try:
        mend_api_response = requests.post(f"{mend_api_url}", data=json.dumps(mend_product_payload), headers=headers)
        return json.loads(mend_api_response.text).get("products")
    except Exception as e:
        return str(e)

#get projects under a product
def get_mend_projects_by_product(product_token):
    mend_project_payload = {
        "requestType": "getAllProjects",
        "userKey": mend_userkey,
        "productToken": product_token
    }
    try:
        mend_api_response = requests.post(f"{mend_api_url}", data=json.dumps(mend_project_payload), headers=headers)        
        return json.loads(mend_api_response.text).get("projects")
    except Exception as e:
        return str(e)


def get_all_mend_projects():
    mend_projects = []
    mend_products = get_mend_products()    
    if (mend_products):
        for product_row in mend_products:
            if(product_row.get("productName") in ("PlatformOnDemand","PlatformOnPrem","Acunetix Sources")):
                mend_projects_by_product_token = get_mend_projects_by_product(product_row.get("productToken"))
            # Ignore products with no project is defined
                if (mend_projects_by_product_token):
                    for project_row_dict in mend_projects_by_product_token:
                        projects_dict = {"productName": product_row.get("productName"),
                                         "projectId": project_row_dict.get("projectId"),
                                         "projectName": project_row_dict.get("projectName"),
                                         "projectToken": project_row_dict.get("projectToken")
                                         }
                        mend_projects.append(projects_dict)    
    return mend_projects


def check_if_filename_matches_mend_project(project, branch):
    global mend_projects
    for mend_project_row in mend_projects:        
        if ((' ' in mend_project_row.get("projectName"))):
            mend_projectName = mend_project_row.get("projectName").lower().split(" ")
            if (any(item for item in mend_projectName if project in item) and mend_project_row.get(
                    "productName").lower() in branch):
                return True
        elif (project in mend_project_row.get("projectName").lower() and mend_project_row.get(
                "productName").lower() in branch):
            return True
    return False


def mend_get_vulns_by_projects(project_token=""):
    # API Note: Only POST requests are accepted.
    mend_payload = {
        "requestType": "getProjectAlertsByType",
        "userKey": mend_userkey,
        "alertType": "SECURITY_VULNERABILITY",
        "projectToken": project_token
    }
    try:
        mend_api_response = requests.post(f"{mend_api_url}", data=json.dumps(mend_payload), headers=headers)
        return json.loads(mend_api_response.text).get("alerts")
    except Exception as e:
        return str(e)


def sonar_parse_api_results(project):
    branch_name = get_branch_name()
    sonar_vul_list = []
    severity = ""
    cur_date_in_dt_format = datetime.utcnow().isoformat()
    sonar_vul_results = sonar_api_integration(project, branch_name)    
    # fetch only not reviewed issues
    if (sonar_vul_results):        
        not_reviewed_sq_sec_issue_list = [item for item in sonar_vul_results if
                                          not (item.get("resolution"))]  # not reviewed items        
        for open_issue in not_reviewed_sq_sec_issue_list:            
            # any(csharp_code in err_msg for csharp_code in csharp_list))
            if (not (any(open_issue.get("component") in item.get("SourceInfo") for item in sonar_vul_list))):                                
                sonar_parsed_result_dict = {
                    "ScanType": "SAST-Sonarqube",
                    "Project": open_issue.get('project'),
                    "Branch": branch_name,
                    "PackageName": open_issue.get("component"),
                    "MatchPkg": drop_prj_name_from_pckg_name(open_issue.get("component")),
                    "ArtifactType": "filesystem",
                    "Msg": open_issue.get('message'),
                    "VulTechFamily": detect_vul_tech_type(open_issue.get("component"), open_issue.get('message')),
                    "CVE": "N-A",
                    "VulnerabilityUrl": "N-A",
                    "CVSV3Score": 0.0,
                    "Severity": open_issue["severity"],
                    "Details": open_issue.get("component"),
                    "SourceInfo": open_issue.get("component"),
                    "Secret": "N-A",
                    "Line": open_issue.get("line"),
                    "InstalledVersion": "N-A",
                    "FixedVersion": "N-A",
                    "ReferenceUrl": "N-A",
                    "PublishedDate": "N-A",
                    "Cwe": "N-A",
                    "ScanDateTimeUtc": cur_date_in_dt_format}
                sonar_vul_list.append(sonar_parsed_result_dict)        
        return sonar_vul_list


def mend_parse_api_results(p_selected_severity_levels, mend_project_list):
    mend_vul_list = []
    cur_date_in_dt_format = datetime.utcnow().isoformat()    
    if (mend_project_list):
        for mend_issue in mend_project_list:            
            mend_severity = mend_issue.get("vulnerability").get("cvss3_severity").upper()
            if (mend_severity in p_selected_severity_levels):
                pkg_name =  mend_issue.get("library").get("groupId")
                pkg_to_match = drop_prj_name_from_pckg_name(pkg_name)
                mend_parsed_result_dict = {
                    "ScanType": "SCA-Whitesource",
                    "Project": mend_issue.get('project').lower(),
                    "Branch": "main",
                    "PackageName": pkg_name,
                    "MatchPkg": pkg_to_match,
                    "ArtifactType": "filesystem",
                    "Msg": mend_issue.get("vulnerability").get("description") +
                           f"\n {mend_issue.get('vulnerability').get('fixResolutionText')} ",
                    "VulTechFamily": mend_issue.get("library").get("type"),
                    "CVE": mend_issue.get("vulnerability").get("name"),
                    "VulnerabilityUrl": mend_issue.get('vulnerability').get('topFix').get("url") if mend_issue.get('vulnerability').get('topFix') is not None else "NA",
                    "CVSV3Score": mend_issue.get("vulnerability").get("cvss3_score"),
                    "Severity": mend_severity,
                    "SourceInfo": mend_issue.get("library").get("filename"),
                    "Secret": "N-A",
                    "SourceLines": "N-A",
                    "InstalledVersion": mend_issue.get("library").get("version"),
                    "FixedVersion": mend_issue.get("vulnerability").get("topFix").get("fixResolution") if mend_issue.get("vulnerability").get("topFix") is not None else "NA",
                    "ReferenceUrl": sca_aggregate_references(mend_issue.get("library").get("references").get("url")),
                    "PublishedDate": mend_issue.get("vulnerability").get("publishDate"),
                    "Cwe": "N-A",
                    "ScanDateTimeUtc": cur_date_in_dt_format}
                mend_vul_list.append(mend_parsed_result_dict)
    return mend_vul_list


if __name__ == "__main__":
    s3_client = boto3.resource('s3')
    sca_selected_severity_levels = [value for levelno, value in sca_severity_levels_dict.items()
                                    if (levelno >= sca_default_min_severity_to_report)]
    sast_selected_severity_levels = [value for levelno, value in sast_severity_levels_dict.items()
                                     if (levelno >= sast_default_min_severity_to_report)]
    is_push_results_to_slack = True
    sast_scan_results = run_sast_scans(sast_selected_severity_levels)
    sca_scan_results = run_sca_scans(sca_selected_severity_levels)
    results = remove_duplicate_issues(results_to_relational_data_schema_dict_list)
    with open(f"{scan_path}/unified_scan_results.json", 'w') as fp:
         json.dump(results, fp, default=str)
    #put_reports_to_s3(s3_client,f"unified_scan_results.json")
    #push_s3_report_url_to_slack()
    push_results_to_slack()
    #create_jira_ticket_from_unified_results()
