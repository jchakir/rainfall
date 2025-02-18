
char pass[80];

struct person {
    int   id;
    char  *name;
}

int m()
{
  time_t t;

  t = time(0);
  return printf("%s - %d\n", pass, t);
}

int main(int argc, char **argv)
{
  FILE *pass_file;
  void *p1;
  void *p2;

  p1 = malloc(8);
  p1->id = 1;
  p1->name = malloc(8);
  p2 = malloc(8);
  p2 = 2;
  p2->name = malloc(8);
  strcpy(p1->name, argv[1]);
  strcpy(p2->name, argv[2]);
  pass_file = fopen("/home/user/level8/.pass", "r");
  fgets(pass, 68, pass_file);
  puts("~~");
  return 0;
}

