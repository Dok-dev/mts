# Tasks from MTS

## Task 1
Составить скрипт на любом доступном языке программирования, который раз в 5 минут производит подключение к БД, забирает из таблицы данные о количестве строк за последние 5 минут. Это количество необходимо отправить в zabbix с помощью zabbix_agent в метрику count_last_5_min. 

Решение: [solution1.py](solution1.py)

## Task 2
БД: Даны две таблицы:

Таблица 1 (Cities): 

| ID   | Country | Name   | Amount_of_Citizens |
| :--- | :------ | :----- | :----------------- |
| 1    | Russia     | Moscow  | 20 000 000 |
| 2    | Ukraine    | Kiev    | 15 000 000 |
| 3    | Belorussia | Minsk   | 10 000 000 |
| 4    | Georgia    | Tbilisi | 7 000 000  |

Таблица 2 (Companies): 

| ID   | City | Name   | Amount_of_Employees |
| :--- | :------ | :----- | :----------------- |
| 1    | Moscow     | Microsoft | 3000 |
| 2    | Minsk    | Dell    | 2500 |
| 3    | Tbilisi | Apple   | 5000 |


2.1 Написать SQL-запрос, который будет выгружать список городов, в которых нет компаний;

Решение:    
```sql
SELECT cities.name FROM cities
 LEFT JOIN companies ON cities.name = companies.city
WHERE companies.name IS NULL
```

2.2. Написать SQL-запрос, который будет выгружать название стран с ТОП-3 компаний по численности сотрудников;

Решение:    
```sql
SELECT cities.country FROM cities
 LEFT JOIN companies ON cities.name = companies.city
WHERE companies.name IS NOT NULL
ORDER BY amount_of_employees DESC
LIMIT 3;
```


## Task 3
Вывести логины всех пользователей в PowerShell из ActiveDirectory или Ldap.

Решение:   
```powershell
(Get-ADUser -Filter *).Name
```

## Task 4
Дан лог
```text
2018-11-14 00:04:18.635 [rabbit-toDataProvider_request_param-76_3136280] [INFO ]:0 r.i.m.e.c.Consumer : consumer-toDataProvider_request_param-76, {"request":{"request_id":"006a9a01-8c2b-4915-ade3-075e1ca2a779","method":"request_param","environment":"stable","version":"14.18.0a","args":{"user_token":"0-3db9a6a483ec494599782fb54675ff5d66e13e942b4e4cd9a43193493cf84b5385cc3f0497394fb6b51ad2d764e38156","param_name":"tariff_uvas"},"create_time":1542143074769},"connection_id":17325,"answer_to":"toWSServer_mtssnjs5.msk.mts.ru_47100"}    
2018-11-14 00:04:18.635 [rabbit-toDataProvider_request_param-76_3136280] [DEBUG]:0 r.i.m.e.c.h.DefaultHandler : Start: method = request_param, param_name = tariff_uvas    
2018-11-14 00:04:18.637 [rabbit-toDataProvider_request_param-76_3136280] [INFO ]:0 MTS-SYSTEM-STAT : sESB request for stat, getTariffPlanByMsisdn. MSISDN = 79999999999    
2018-11-14 00:04:23.729 [rabbit-toDataProvider_request_param-76_3136280] [ERROR]:0 MTS-SYSTEM-STAT : sESB ERROR for stat, getTariffPlanByMsisdn. ErrorClass = ru.mts.uvas.syncrequest.UvasException_Exception . error = javax.xml.ws.WebServiceException: java.net.SocketTimeoutException: Read timed out. MSISDN = 79999999999   
2018-11-14 00:04:23.729 [rabbit-toDataProvider_request_param-76_3136280] [INFO ]:0 r.i.m.e.c.Consumer : Answer to: toWSServer_mtssnjs5.msk.mts.ru_47100, value: {"request":{"request_id":"006a9a01-8c2b-4915-ade3-075e1ca2a779","status":"ERROR","result":null},"connection_id":17325}    
2018-11-14 00:04:23.730 [rabbit-toDataProvider_request_param-76_3136280] [DEBUG]:0 r.i.m.e.c.Consumer : send ack to consumer-toDataProvider_request_param-76 ok    
```

Решение:   
JSON-запрос RabbitMQ параметра tariff_uvas для номера 79999999999 c toWSServer_mtssnjs5.msk.mts.ru. Затем ответ с ошибкой приложения java из за таймаута при попытке соединения, сообщение об ошибочном статусе выполения запроса.

## Task 5
Выбрать из лога строки с запросом метода getBalances и типом запроса REQUEST, затем сделать выборку ТОП-3 по самым частым номерам телефонов (файл с логом – 5.log)

Решение:   
```bash
grep 'getBalances REQUEST' 5.log | awk -F "=" '{print $NF}' | sort| uniq -c | sort -rnk1 | head -n3
```

## Task 6
Есть дамп (открывается через WireShark) (файл с дампом – dump.pcap)
Опишите, что происходит в дампе, есть ли какие проблемы. Если есть проблемы постарайтесь сделать несколько предположений о причинах проблемы.

Решение:   
Устройство Apple с IP 192.168.1.35 и с порта 57552 пытается открыть TCP соединение с IP 213.87.44.13 (Zyxel) на порт 3237, посылая SYN. Вместо ответа ACK c получает RST, ACK.
Причин может быть также несколько. Обычно это означает, что порт, по которому пытаются открыть соединение, недоступен. Сервер отключен, сервер занят или такой порт закрыт. Поэтому происходит сброс соединения.    
Далее поисходит успешное соединение с корректным завершением FIN, ACK.

## Task 7
Составьте команду для снятия tcpdump в Linux со следующими условиями:
 A.	Без ограничения размера пакетов
 B.	Адрес источника и адрес назначения 192.168.0.1 (или любой другой для удобства)
 C.	Полученный результат записать в файл
 D.	Указать сетевой интерфейс
 
Решение:   
```bash
tcpdump -i eth0 host 192.168.0.1 -s 0 -w dump.cap
```

## Task 8
Используя приложенный файл 8.txt, содержащий образец данных БД Elastic, написать DSL-запрос, который:
8.1.	Выгрузит данные после 00:01:31 23.06.2019 включительно;

Решение:	
```text
POST clients/_search
{
  "query": {
      "range" : {
            "@timestamp" : {
                "gte": "2019-06-23T00:01:31.000Z", 
				"lte": "now"
            }
        }
  }
}
```

8.2.	Выгрузит данные, сгруппированные по полю «method». 

Решение:	
```text
POST clients/_search
{
   "size": 0, 
   "aggregations": {
      "the_name": {
         "terms": {
            "field": "method"
        }
      }
   }
}
```

8.3.	Используя получившейся запрос п. 6.2. дополнительно включить в группировку данные по полю «response».

Решение:	
```text
POST clients/_search
{
   "size": 0, 
   "aggregations": {
      "the_name": {
         "terms": {
            "field": "method"
        },
		"aggregations": {
		    "the_name": {
				"terms": {
					"field": "response"
				}
			}
		}
      }
   }
}
```

## Task 9
Написать конфигурацию Prometheus для сбора метрик при помощи node exporter и отсылки их в alertmanager (сервера и пути к файлам можете выбирать произвольные)    

Решение:	
`cat /etc/prometheus/prometheus.yml`
```yaml
global:
  scrape_interval: 15s # Set the scrape interval to every 15 seconds. Default is every 1 minute.
  evaluation_interval: 15s # Evaluate rules every 15 seconds. The default is every 1 minute.
  # scrape_timeout is set to the global default (10s).

# Alertmanager configuration
alerting:
  alertmanagers:
    - static_configs:
        - targets:
          # - alertmanager:9093

# Load rules once and periodically evaluate them according to the global 'evaluation_interval'.
rule_files:
  # - "first_rules.yml"
  # - "second_rules.yml"
  - "alert.rules.yml"

# A scrape configuration containing exactly one endpoint to scrape:
# Here it's Prometheus itself.
scrape_configs:
  # The job name is added as a label `job=<job_name>` to any timeseries scraped from this config.
  - job_name: "prometheus"

    # metrics_path defaults to '/metrics'
    # scheme defaults to 'http'.

    static_configs:
      - targets: ["localhost:9090"]
  - job_name: 'node_exporter_clients'
    scrape_interval: 2s
    static_configs:
      - targets: ['192.168.17.146:9100', '10.10.0.2:9100', '172.16.29.200:9100']
```

9.1	Добавить алерт на загруженность CPU и настроить отправку на почту (почта находится на 25 порту на локальной машине, без пароля и SSL)    

Решение:	
```cat /etc/prometheus/alert.rules.yml```
```yaml
- name: alert.rules
  rules:
  - alert: CPU_Highload
    expr: avg(irate(node_cpu_seconds_total{mode="idle"}[1m]) * 100) >= 95
    for: 1m
    labels:
      severity: critical
    annotations:
      description: "{{ $labels.instance }} has a average CPU idle (current value: {{ $value }}s)"
      summary: "High CPU usage on {{ $labels.instance }}"
```

```cat /etc/alertmanager/alertmanager.yml```
```yaml
global:
  smtp_from: monitoring@mts.ru

route:
  group_by: ['alertname', 'instance', 'severity']
  group_wait: 10s
  group_interval: 5m
  repeat_interval: 1h
  receiver: 'web.hook'

  routes:
    - receiver: send_email
      match:
        alertname: CPU_Highload

receivers:
  - name: 'web.hook'
    webhook_configs:
      - url: 'http://127.0.0.1:5001/'
 - name: send_email
   email_configs:
   - to: alert@mts.ru
     smarthost: localhost:25
     require_tls: false

inhibit_rules:
  - source_match:
      severity: 'critical'
    target_match:
      severity: 'warning'
    equal: ['alertname', 'dev', 'instance']
```