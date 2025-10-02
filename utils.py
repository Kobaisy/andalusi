import random
import string
from your_app import db
from your_app.models import Code  # adjust import to your actual model

def generate_unique_code(length=10):
    return ''.join(random.choices(string.ascii_uppercase + string.digits, k=length))

def bulk_generate_codes(n=1_000_000, batch_size=10_000):
    for _ in range(0, n, batch_size):
        batch = []
        for _ in range(batch_size):
            code_str = generate_unique_code()
            batch.append(Code(code=code_str, status='unused'))
        db.session.bulk_save_objects(batch)
        db.session.commit()

