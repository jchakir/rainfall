int run()
{
  fwrite("Good... Wait what?\n", 1, 0x13, stdout);
  return system("/bin/sh");
}

int  main()
{
  char s[64];

  gets(s);
  return 0;
}
