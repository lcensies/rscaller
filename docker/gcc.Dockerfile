FROM gcc:15.1.0

COPY scripts /app/scripts 

RUN apt update && apt install -y gawk bison
# Might need different version based on the
# kernel
RUN /app/scripts/install_glibc.sh 2.38

