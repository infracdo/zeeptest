# Use Python 3.8.10 base image
FROM python:3.8.10

# Set working directory in the container
WORKDIR /app

# Copy the requirements file into the container
COPY requirements.txt .

# Install dependencies from requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application code
COPY . .

# Expose the port Flask runs on (default is 5000)
EXPOSE 5000

# Set the Flask environment variables and run the app
ENV FLASK_APP=app.py
#ENV FLASK_ENV=production

# Command to run the Flask app
CMD ["flask", "run", "--host=0.0.0.0"]
