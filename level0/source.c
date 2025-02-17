

int main (int argc, char** argv) {

  int   n;
  int   egid, euid;
  char*  binsh[2];

  n = atoi(argv[1]);
  if (n == 423) {
    binsh[0] = srtdup("/bin/sh");
    binsh[1] = 0;
    egid = getegid();
    euid = geteuid();
    setresgid();
    setresuid();
    execv("/bin/sh", binsh, 0);
  } else {
    write(1, "No !\n", 5);
  }
}

