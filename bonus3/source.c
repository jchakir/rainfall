int main(int argc, const char **argv)
{
  char buff[132];
  FILE *pass_file;
  int i;

  pass_file = fopen("/home/user/end/.pass", "r");
  memset(buff, 0, sizeof(buff));
  if ( !pass_file || argc != 2 )
    return -1;
  fread(buff, 1, 66, pass_file);
  ptr[65] = 0;
  i = atoi(argv[1]);
  ptr[i] = 0;
  fread(buff + 66, 1, 65, pass_file);
  fclose(pass_file);
  if ( !strcmp(buff, argv[1]) )
    execl("/bin/sh", "sh", 0);
  else
    puts(buff + 66);
}
