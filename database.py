from flask_mysqldb import MySQL
import configparser
import os, asyncio

# MySQL Database Class

class Database:
    def __init__(self, flask_app):
        """Database object for Flask web app"""
        self.__config = configparser.RawConfigParser()
        self.__config.read("db.config")

        with flask_app.app_context():
            flask_app.config["SECRET_KEY"] = self.__config.get("database-config", "SECRET_KEY")
            flask_app.config["MYSQL_DB"] = self.__config.get("mysql-config", "MYSQL_DB")
            flask_app.config["MYSQL_HOST"] = self.__config.get("mysql-config", "MYSQL_HOST")
            flask_app.config["MYSQL_USER"] = self.__config.get("mysql-config", "MYSQL_USER")
            flask_app.config["MYSQL_PASSWORD"] = self.__config.get("mysql-config", "MYSQL_PASSWORD")
            flask_app.config["MYSQL_CURSORCLASS"] = self.__config.get("mysql-config", "MYSQL_CURSORCLASS")

            self.mysql = MySQL(flask_app)
            self.querySet("SET GLOBAL max_allowed_packet=17179869184")

    def queryGet(self, query_str: str, value_tuple: tuple = None) -> dict:
        """Performs a query to the database and fetches one result."""
        with self.mysql.connect as conn:
            cursor = conn.cursor()
            cursor.execute(query_str, value_tuple)
            results = cursor.fetchone()
            cursor.close()

        return results
    
    def queryGetAll(self, query_str: str, value_tuple: tuple = None) -> list[dict]:
        """Performs a query to the database and fetches all results."""
        with self.mysql.connect as conn:
            cursor = conn.cursor()
            cursor.execute(query_str, value_tuple)
            results = cursor.fetchall()
            cursor.close()

        return results

    def querySet(self, query_str: str, value_tuple: tuple = None) -> None:
        """Performs a query to the database and commits any changes made to the database."""
        with self.mysql.connect as conn:
            cursor = conn.cursor()
            cursor.execute(query_str, value_tuple)
            conn.commit()
            cursor.close()
    
    async def backupDB(self):
        """Creates a backup of the current database asynchronously. Set to backup every 30 minutes."""
        while True:
            os.system('mariadb-dump --skip-ssl -h {host} -u {user} {db} > instance/{db}.sql'.format(
                host = self.__config.get("mysql-config", "MYSQL_HOST"),
                user = self.__config.get("mysql-config", "MYSQL_USER"),
                db = self.__config.get("mysql-config", "MYSQL_DB")
            ))
            print("[i] Database backed up. Next in 30 minutes...")
            await asyncio.sleep(1800)