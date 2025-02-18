char* auth;
char* service;

int main()
{
  char buff[130];

  while ( 1 )
  {
    printf("%p, %p \n", auth, service);
    if ( !fgets(buff, 128, stdin) )
      break;
    if ( !memcmp(buff, "auth ", 5) )
    {
      auth = malloc(4);
      *auth = 0;
      if ( strlen(buff + 5) <= 30 )
        strcpy(auth, buff + 5);
    }
    if ( !memcmp(buff, "reset", 5) )
      free(auth);
    if ( !memcmp(buff, "service", 6) )
      service = strdup(buff + 7);
    if ( !memcmp(buff, "login", 5) )
    {
      if ( *(auth + 32) )
        system("/bin/sh");
      else
        fwrite("Password:\n", 1, 10, stdout);
    }
  }
  return 0;
}

