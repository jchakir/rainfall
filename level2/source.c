char *p()
{
  char  s[64];
  void  *retaddr;

  gets(s);
  if ( (retaddr & 0xb0000000) == 0xb0000000 )
  {
    printf("(%p)\n", retaddr);
    exit(1);
  }
  puts(s);
  return strdup(s);
}


int main(int argc, const char **argv, const char **envp)
{
  p();
  return 0;
}
