import redis
from redlock import Redlock
from your_app import db
from your_app.models import Code

redis_client = redis.Redis.from_url("redis://localhost:6379/0")  # Adjust URL
dlm = Redlock([{"host": "localhost", "port": 6379}])

def redeem_code(code_str, user_id):
    lock_key = f"lock:redeem:{code_str}"
    lock = dlm.lock(lock_key, 2000)  # 2 second lock
    if not lock:
        return False, "Redemption busy, try again"

    try:
        code = Code.query.filter_by(code=code_str, status='unused').first()
        if not code:
            return False, "Invalid or already redeemed code"

        # mark code as redeemed
        code.status = 'redeemed'
        code.redeemed_by = user_id
        code.redeemed_at = datetime.utcnow()

        db.session.commit()
        return True, "Code redeemed successfully"
    finally:
        dlm.unlock(lock)

