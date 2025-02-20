int main() {
  char dest[40];
  int n;

  n = atoi(argv[1]);
  if ( n > 9 )
    return 1;
  memcpy(dest, argv[2], 4 * n);
  if ( n == 1464814662 )
    execl("/bin/sh", "sh", 0);
  return 0;
}
