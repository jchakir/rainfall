
void p(char *dest, char *s) {
  char buf[4104];

  puts(s);
  read(0, buf, 4096);
  *strchr(buf, 10) = 0;
  strncpy(dest, buf, 20);
}

void pp(char *dest) {
  char s1[20];
  char s2[28];

  p(s1, " - ");
  p(s2, " - ");
  strcpy(dest, s1);
  dest[strlen(dest)] = " ";
  strcat(dest, s2);
}

int main() {
  char buff[42];

  pp(buff);
  puts(buff);
}

