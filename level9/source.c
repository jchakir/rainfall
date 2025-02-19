
class N {
public:
  virtual int operator+(const N &other) const {
      return this->value + other.value;
  }

  virtual int operator-(const N &other) const {
      return this->value - other.value;
  }

  void setAnnotation(char *s)
  {
    size_t len;

    len = strlen(s);
    return memcpy(annotation, s, len);
  }

  N(int val) : value(val) {}
  virtual ~N() {}

private:
  char annotation[100];
  int value;
};

int main(int argc, const char **argv) {
  if (argc <= 1) std::exit(1);

  N* obj1 = new N(5);
  N* obj2 = new N(6);

  obj1->setAnnotation(argv[1]);

  obj2 + obj1;
}

