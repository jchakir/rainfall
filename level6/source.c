
void n() {
  system("/bin/cat /home/user/level7/.pass");
}

void m() {
  puts("Nope");
}

int main(int argc, char* argv[]) {
  void *func;
  char *buff;

  buff = malloc(64);
  func = malloc(4);
  *func = m;
  strcpy(buff, argv[1]);
  (*func)();
}
