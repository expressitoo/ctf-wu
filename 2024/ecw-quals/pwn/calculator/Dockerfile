FROM debian:bookworm-20240423

RUN useradd -M vuln
RUN mkdir /vuln
WORKDIR /vuln
COPY vuln .
COPY ynetd /bin
COPY get_flag /bin/get_flag
RUN chown root:root vuln /bin/get_flag /bin/ynetd
RUN chmod 0755 vuln /bin/get_flag /bin/ynetd

CMD ["ynetd", "-p", "1337", "-u", "vuln", "-d", "/vuln", "-lt", "10", "./vuln"]
EXPOSE 1337
