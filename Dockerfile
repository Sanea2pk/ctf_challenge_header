# Use an official Python runtime as a parent image
FROM python:3.10-slim

# Set the working directory in the container
WORKDIR /app

# Copy the current directory contents into the container at /app
COPY . /app

# Install any needed packages specified in requirements.txt
RUN pip install --no-cache-dir flask

# Make port 5000 available to the world outside this container
EXPOSE 5000

# Define environment variable to ensure Python outputs everything to the console
ENV PYTHONUNBUFFERED=1

# Run app.py when the container launches
CMD ["python", "main.py"]
