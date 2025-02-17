int m;

void p(char *format)
{
  printf(format);
}

void n()
{
  char buffer[520];

  fgets(buffer, 512, stdin);
  p(buffer);
  if ( m == 16930116 )
    system("/bin/cat /home/user/level5/.pass");
}

int main()
{
  n();
}
