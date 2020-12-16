FROM ubuntu:20.04
RUN apt update
RUN apt-get install -y python3 python3-pip
RUN pip3 install pyyaml
RUN useradd -m sslcheck
COPY check.py /home/sslcheck/check.py
RUN chmod 755 /home/sslcheck/check.py
RUN chown sslcheck /home/sslcheck/check.py
USER sslcheck
WORKDIR /home/sslcheck/
ENTRYPOINT ["/home/sslcheck/check.py", "/config.yml"]
