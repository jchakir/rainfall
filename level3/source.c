int m;

int v()
{
  int result;
  char buffer[520];

  fgets(buffer, 512, stdin);
  printf(buffer);
  if ( m == 64 )
  {
    fwrite("Wait what?!\n", 1, 0xC, stdout);
    system("/bin/sh");
  }
}

int main()
{
  v();
}

