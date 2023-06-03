
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import Select
from selenium.common.exceptions import NoSuchElementException, NoAlertPresentException
import unittest, time, re
from zapv2 import ZAPv2
from selenium.webdriver.common.proxy import *
from pprint import pprint
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import A4
from json2html import *
import json
import mariadb
import sys
import uuid

myProxy = "http://127.0.0.1:8080"

proxy = Proxy({
    'proxyType': ProxyType.MANUAL,
    'httpProxy': myProxy,
    'ftpProxy': myProxy,
    'sslProxy': myProxy,
    'noProxy': ''})

driver = webdriver.Firefox(proxy=proxy)
driver.implicitly_wait(30)
base_url = "https://sso.vecindariosuite.com/iniciar-sesion"
verificationErrors = []
accept_next_alert = True
driver.maximize_window()
driver.get(base_url)

try:
    conn = mariadb.connect(
        user="hqa",
        password="hqa",
        host="localhost",
        port=3306,
        database="uqa"
    )
except mariadb.Error as e:
    print(f"Error connecting to MariaDB Platform: {e}")
    sys.exit(1)

apiKey = 'rkum9ecbtkrvrfo8ifil0jhl19'

zap = ZAPv2(apikey=apiKey, proxies={'http': 'http://127.0.0.1:8080'})
cur = conn.cursor()
cur.execute("select testId, gId, state, params from matriz_test mt where testId like '%Login%'")
testId = ""
gId = ""
for testIdx, gIdx, state, params in cur:
    testId =testIdx
    gId = gIdx
    print(f"testIdx: {testIdx}, gId: {gIdx}, state: {state} , params: {params}")


time.sleep(10)
driver.find_element(By.XPATH,"//button[contains(@class,'suite-button default')]").click()
driver.find_element(By.NAME,"email").send_keys("testing.vecindario.9@vecindario.com")
driver.find_element(By.XPATH,"//button[contains(@class,'suite-button default')]").click()
time.sleep(6)
driver.find_element(By.NAME,"0").send_keys("9")
driver.find_element(By.NAME,"1").send_keys("9")
driver.find_element(By.NAME,"2").send_keys("9")
driver.find_element(By.NAME,"3").send_keys("9")
driver.find_element(By.NAME,"4").send_keys("9")
driver.find_element(By.NAME, "5").send_keys("9")
time.sleep(10)
driver.quit()


owasp = ""
name = ""
url = ""
detail = ""
recommendation = ""
resolution = ""
confidence = ""
alertt = 0.50
while int(zap.pscan.records_to_scan) > 0:
    # Loop until the passive scan has finished
    print('Records to passive scan : ' + zap.pscan.records_to_scan)
    time.sleep(2)

print('Passive Scan completed')
#Print Passive scan results/alerts
print('Hosts: {}'.format(', '.join(zap.core.hosts)))
print('Alerts: ')
pprint(zap.core.alerts())


st = 0
pg = 5000
alert_dict = {}
alert_count = 0
#alerts = zap.core.alerts(baseurl=base_url, start=st, count=pg)
alerts = zap.core.alerts()
blacklist = [1,2]

while len(alerts) > 0:
    print('Reading ' + str(pg) + ' alerts from ' + str(st))
    alert_count += len(alerts)
    for alert in alerts:
        plugin_id = alert.get('pluginId')

        if plugin_id in blacklist:
            continue
        if alert.get('risk') == 'High':

            if owasp != alert.get('risk'):
                owasp = alert.get('risk')
                name = alert.get('name')
                url = alert.get('reference')
                datail = alert.get('description')
                recommendation = alert.get('other')
                resolution = alert.get('solution')
                confidence = alert.get('confidence')
                alertt = 0.80

            continue
        if alert.get('risk') == 'Medium':

            if owasp != alert.get('risk') and owasp != 'High':
                owasp = alert.get('risk')
                name = alert.get('name')
                url = alert.get('reference')
                datail  = alert.get('description')
                recommendation = alert.get('other')
                resolution = alert.get('solution')
                confidence = alert.get('confidence')
                alertt = 0.65

            # Trigger any relevant postprocessing
            continue
        if alert.get('risk') == 'Informational':

            # Ignore all info alerts - some of them may have been downgraded by security annotations
            continue
    st += pg
    alerts = zap.alert.alerts(start=st, count=pg)


file = open("sample.html","w")
file.write(json2html.convert(json = zap.core.alerts()))
file.close()
upt = conn.cursor()
print("entro")
print(gId)



curtest = conn.cursor()
curtest.execute("select (select count(gId) from uqa.matriz_test where gId = ?) as total,  (select count(gId) from uqa.matriz_test where gId = ?  and state = 'complete') as complete", (gId, gId))
coverage = 1
for total, complete in curtest:
    coverage =complete/total
    print(coverage)
conn.commit()
curstakeholder = conn.cursor()
curstakeholder.execute("select num_elements  as stakeholder from uqa.user_stroy_technical where gid = ? limit 1 ",  (gId, ))
stakeholder2 = 0
for stakeholder in curstakeholder:
    stakeholder2 =stakeholder[0] * 0.12
    print(stakeholder2)
conn.commit()

upt.execute("UPDATE uqa.matriz_test SET state='complete' where testId = ? and  gId= ?",(testId, gId) )
conn.commit()
upt2 = conn.cursor()
upt2.execute("INSERT INTO uqa.user_story_result (gId, id, owasp, urlScript, urlAlert, detail, recommendation, solution, technologie, src, alert,resolution, stakeholder) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,?, ?)", (gId, str(uuid.uuid4()), owasp, name, url, datail, recommendation, resolution, confidence, str(json.dumps(zap.alert.alerts(start=0, count=10))), alertt, coverage, stakeholder2))
conn.commit()
print("entro2")