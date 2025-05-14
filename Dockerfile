# Use official Python image
FROM python:3.10-slim

# Set working directory
WORKDIR /app

# Copy requirements first and install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy rest of the app
COPY . .

# Expose port Elastic Beanstalk expects
EXPOSE 5000

# Run Flask app via Gunicorn (EB-friendly)
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "application:application"]
