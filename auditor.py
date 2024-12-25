from datetime import datetime

def add_log(user_id: int, event_type: str, description: str) -> tuple:
    current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')
    query_str = "INSERT INTO audit_log (id, timestamp, user_id, event_type, description) VALUES (NULL,%s,%s,%s,%s)"
    return (query_str, (current_time, user_id, event_type, description))

