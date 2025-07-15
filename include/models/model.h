#ifndef MODEL_H
#define MODEL_H

// Todas las structs "Model" deben implementar esta función
typedef struct ModelInterface {
    void (*deserialize_xml)(void *self, const char *xml);
} ModelInterface;

#endif
