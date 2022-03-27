import time
import psycopg2
from pyzabbix import ZabbixMetric, ZabbixSender

def getRowsNamber(server):
    try:
        # Создаем соединение с нашей базой данных
        conn = psycopg2.connect(dbname='mts', user='user',
                                password='Z123456Z', host=server)
        # Создаем курсор, специальный объект который делает запросы и получает их результаты
        cursor = conn.cursor()

        # Создадим тригер для логирования времени записей в отдельной таблице events_time
        cursor.execute("""DO $$
        BEGIN;
            IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'rows_time'::regclass) THEN
                CREATE FUNCTION insert_time()
                    RETURNS trigger
                    LANGUAGE 'plpgsql'
                AS $BODY$
                     INSERT INTO events_time SET id = NEW.id , datetime = NOW();
                $BODY$;
                
                ALTER FUNCTION insert_time()
                    OWNER TO user;
                    
                CREATE TRIGGER 'rows_time'
                    AFTER INSERT ON events FOR EACH ROW EXECUTE PROCEDURE insert_time()
            END IF;
        END;
        $$;""")

        cursor.execute("""
        SELECT * FROM events_time;
        """)

        number = len(cursor.fetchall())

        cursor.execute("""
        TRUNCATE events_time;
        $""")

        return number
        # Не забываем закрыть соединение с базой данных
        conn.close()
    except psycopg2.DatabaseError as err:
        print('SQL error: {0}'.format(err))
        return [0,'SQL error: {0}'.format(err)]

SQLServer = 'posgree_node0'
metrics = []

m = ZabbixMetric(SQLServer, 'count_last_5_min', str(getRowsNamber(SQLServer)))
metrics.append(m)
zbx = ZabbixSender(zabbix_server='127.0.0.1', zabbix_port=10051, chunk_size=1)
zbx.send(metrics)

time.sleep(300)