# Use an official Python runtime as a parent image
FROM python:3.10.10

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1

# Set the working directory
WORKDIR /app

# Install dependencies
COPY requirements.txt /app/
RUN pip install -r requirements.txt

RUN pip install mysqlclient && pip install django-filter && pip install requests &&  pip install requests-mock

# Copy the project code into the container
COPY ./ /app/

ENTRYPOINT [ "/bin/sh", "-c" ]
CMD ["./script.sh"]