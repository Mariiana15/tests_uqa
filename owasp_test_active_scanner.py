#!/usr/bin/env python
import time
from pprint import pprint
from zapv2 import ZAPv2
from selenium.webdriver.common.proxy import *
from pprint import pprint
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import Select
from selenium.common.exceptions import NoSuchElementException, NoAlertPresentException

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

apiKey = 'rkum9ecbtkrvrfo8ifil0jhl19'

zap = ZAPv2(apikey=apiKey, proxies={'http': 'http://127.0.0.1:8080'})

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

# TODO : explore the app (Spider, etc) before using the Active Scan API, Refer the explore section
pprint('Active Scanning target {}'.format(base_url))
scanID = zap.ascan.scan(base_url)
while int(zap.ascan.status(scanID)) < 100:
    # Loop until the scanner has finished
    print('Scan progress %: {}'.format(zap.ascan.status(scanID)))
    time.sleep(5)

print('Active Scan completed')
# Print vulnerabilities found by the scanning
print('Hosts: {}'.format(', '.join(zap.core.hosts)))
print('Alerts: ')
pprint(zap.core.alerts(baseurl=base_url))