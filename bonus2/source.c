int language;

void greetuser(char *src) {
  char dest[72];

  switch ( language ) {
    case 2:
      strcpy(dest, "Goedemiddag! ");
      break;
    case 0:
      strcpy(dest, "Hello ");
      break;
  }
  strcat(dest, src);
  puts(dest);
}

int main(int argc, const char **argv) {
  char s1[76];
  char s2[76];
  char *lang;

  if ( argc != 3 )  return 1;
  memset(s2, 0, sizeof(dest));
  strncpy(s2, argv[1], 40);
  strncpy(s2 + 40, argv[2], 32);
  lang = getenv("LANG");
  if ( lang ) {
    if ( !memcmp(lang, "fi", 2) )         language = 1;
    else if ( !memcmp(lang, "nl", 2) )    language = 2;
  }
  memcpy(s1, s2, sizeof(s1));
  greetuser(s1);
}
