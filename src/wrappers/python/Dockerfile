FROM python:3.8-slim-buster

RUN pip install pygroupsig
RUN mkdir /root/pygroupsig
WORKDIR /root/pygroupsig
COPY samples/join-mem-seq1.py /root/pygroupsig
COPY samples/join-mem-seq3.py /root/pygroupsig
COPY samples/sign.py /root/pygroupsig
COPY samples/blind.py /root/pygroupsig
COPY samples/unblind.py /root/pygroupsig
