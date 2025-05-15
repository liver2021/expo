from random import choices
import psycopg2
from faker import Faker
from random import randint
from datetime import datetime
import calendar
from dotenv import load_dotenv
import os

load_dotenv()  # Load variables from .env file

conn = psycopg2.connect(
    dbname=os.getenv("DB_NAME"),
    user=os.getenv("DB_USER"),
    password=os.getenv("DB_PASSWORD"),
    host=os.getenv("DB_HOST"),
    port=os.getenv("DB_PORT")
)

cur = conn.cursor()
fake = Faker()

def generate_transactions_for_month(user_id, month, year):
    transaction_type_choices = ['Ausgaben', 'Zuflüsse']
    t_weights = [0.8, 0.2]  # mostly expenses

    categories = ['Lebensmittel', 'Miete', 'Versicherungen', 'Freizeit', 'Reisen', 'Gesundheit', 'Transport', 'Haushalt', 'Bildung', 'Sonstiges']
    weights = [0.15,0.1,0.1,0.1,0.1,0.1,0.1,0.1,0.05,0.1]

    # Separate limits for Ausgaben (Expenses) and Zuflüsse (Inflows)
    monthly_limits_expenses = {
        'Lebensmittel': 800,
        'Miete': 1000,
        'Versicherungen': 300,
        'Freizeit': 300,
        'Reisen': 400,
        'Gesundheit': 250,
        'Transport': 200,
        'Haushalt': 300,
        'Bildung': 150,
        'Sonstiges': 250
    }

    monthly_limits_inflows = {
        'Lebensmittel': 0,
        'Miete': 0,
        'Versicherungen': 0,
        'Freizeit': 0,
        'Reisen': 0,
        'Gesundheit': 0,
        'Transport': 0,
        'Haushalt': 0,
        'Bildung': 0,
        'Sonstiges': 0,
        'Salary': 5000  # Optionally add inflow category like salary
    }

    # Merge inflow categories if needed
    if 'Salary' not in categories:
        categories.append('Salary')
        weights.append(0.05)

    # Tracking
    category_totals_expenses = {cat: 0 for cat in categories}
    category_totals_inflows = {cat: 0 for cat in categories}

    attempts = 0
    max_attempts = 5000

    while attempts < max_attempts:
        attempts += 1

        category = choices(categories, weights)[0]
        transaction_type = choices(transaction_type_choices, t_weights)[0]
        amount = round(randint(10, 200), 2)
        day = randint(1, calendar.monthrange(year, month)[1])
        transaction_date = datetime(year, month, day)

        if transaction_type == 'Ausgaben':
            if category not in monthly_limits_expenses:
                continue
            if category_totals_expenses[category] + amount > monthly_limits_expenses[category]:
                continue
            category_totals_expenses[category] += amount

        elif transaction_type == 'Zuflüsse':
            if category not in monthly_limits_inflows:
                continue
            if category_totals_inflows[category] + amount > monthly_limits_inflows[category]:
                continue
            category_totals_inflows[category] += amount

        cur.execute("""
            INSERT INTO transaction (category, transaction_type, amount, users_id, created_at)
            VALUES (%s, %s, %s, %s, %s)
        """, (category, transaction_type, amount, user_id, transaction_date))

# Generate data
user_id = 3
for month in range(1, 13):
    generate_transactions_for_month(user_id, month, 2025)

conn.commit()
cur.close()
conn.close()
