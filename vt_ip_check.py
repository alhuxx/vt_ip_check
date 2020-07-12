#!usr/bin/env python
import sys
import requests
import re

virus_total_api_key = ''  # Your VirusTotal API key here.
target_ip_address = sys.argv[1]


def vt_ip_query(api_key, target_ip):
    api3_url = 'https://www.virustotal.com/api/v3/ip_addresses/{}'.format(target_ip)
    http_headers = {'x-apikey': '{}'.format(api_key)}
    response = requests.request('GET', api3_url, headers=http_headers)
    return response.text


vt_response = vt_ip_query(virus_total_api_key, target_ip_address)

as_search_pattern = re.compile(r'"as_owner":\s"(.+)",\n.+"asn":\s(\d+),\n.+"continent":\s"(.+)",\n.+"country":\s"(.+)"')
as_search = as_search_pattern.search(vt_response)

vt_analysis_results = re.findall(r'"engine_name":\s"(.+)",\n.+"method":\s".*",\n.+"result":\s"(.+)"', vt_response)

local_vt_results_dict = {
    "clean": 0,
    "suspicious": 0,
    "malicious": 0,
    "malware": 0,
    "unrated": 0,
}

vt_results_dict_pointer = 0

for entry in vt_analysis_results:

    vt_result = vt_analysis_results[vt_results_dict_pointer][1]

    for key, value in local_vt_results_dict.items():
        if key == vt_result:
            local_vt_results_dict[key] += 1

    vt_results_dict_pointer += 1

largest_vt_result_value = 0

for key, value in local_vt_results_dict.items():
    if value > largest_vt_result_value:
        largest_vt_result_value = value
        largest_vt_result_category = key


print('\n' + '-' * 25 + ' REPORT FOR {} '.format(target_ip_address) + '-' * 25)
print('----- Autonomous System Info -----\nAS Owner: {}\nAS Number: {}\nCountry: {}'.format(as_search.group(1), as_search.group(2), as_search.group(4)))
print('\n----- Search Results -----\nVT analysis report is mostly: {}'.format(largest_vt_result_category.upper()))
for key, value in local_vt_results_dict.items():
    print('{}: {}'.format(key.capitalize(), value))
