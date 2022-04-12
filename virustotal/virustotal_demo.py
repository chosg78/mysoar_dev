import demisto_sdk
import os
import subprocess
import requests


API_KEY = 'd9cec3d1958eae65077d5723bdbb643f2ff1f14c614deb49d5391f6317578936'
VT_URL = 'https://www.virustotal.com/vtapi/v2/url/scan'
TARGET_URL = 'http://amaz0n.zhongxiaoyang.top'

params = {'apikey': API_KEY, 'url': TARGET_URL}
response_scan = requests.post(VT_URL, data=params)
result_scan = response_scan.json()

scan_id = result_scan['scan_id']  # 결과를 출력을 위해 scan_id 값 저장

# URL 스캔 시작 안내, 60초 대기
print('Virustotal File Scan Start (60 Seconds Later) : ', TARGET_URL, '\n')

# 스캔 후 1분 대기
# time.sleep(5)
#
# 바이러스토탈 URL 스캔 결과 주소
url_report = 'https://www.virustotal.com/vtapi/v2/url/report'

# 결과 파일 찾기 위해 scan_id 입력
url_report_params = {'apikey': API_KEY, 'resource': scan_id}

# 바이러스토탈 URL 스캔 결과 리포트 조회
response_report = requests.get(url_report, params=url_report_params)

# 점검 결과 데이터 추출
report = response_report.json()  # 결과 값을 report에 json형태로 저장
report_verbose_msg = report.get('verbose_msg')
report_scans = report.get('scans')  # scans 값 저장
report_scans_vendors = list(report['scans'].keys())  # Vendor 저장
report_scans_vendors_cnt = len(report_scans_vendors)  # 길이 저장
report_scan_data = report.get('scan_data')

print(report_verbose_msg, '\n')
#time.sleep(1)

# 파일 스캔 결과 리포트 데이터 보기
print('Scan Data (UTC) :', report_scan_data)
print('Scan URL Vendor CNT: ', report_scans_vendors_cnt, '\n')

# 바이러스 스캔 엔진사 별 데이터 정리
numbers = 1
for vendor in report_scans_vendors:
    outputs = report_scans[vendor]
    outputs_result = report_scans[vendor].get('result')
    outputs_detected = report_scans[vendor].get('detected')

    # outputs_detected = True, False
    # outputs_result = clean site, unrated site, malware site, malicious site, Phishing site
    if outputs_result != 'clean site':
        if outputs_result != 'unrated site':
            print(f'[No].{numbers}',
                  ",[Vendor Name]:", vendor,
                  ',[Vendor Result]:', outputs_result,
                  ',[Vendor Detected]:', outputs_detected)
            numbers += 1


