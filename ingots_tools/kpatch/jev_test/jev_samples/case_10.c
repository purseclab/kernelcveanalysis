#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct token {
    uint64_t subject_uid;
    uint64_t tenant_id;
    bool is_admin;
};

struct update_request {
    uint64_t resource_id;
    uint64_t claimed_owner_uid;
    uint64_t claimed_tenant_id;
    const void *new_value;
    size_t new_value_size;
};

struct resource {
    uint64_t owner_uid;
    uint64_t tenant_id;
};

extern struct resource *load_resource(uint64_t resource_id);
extern int store_value(struct resource *resource, const void *value, size_t size);

static bool may_modify(const struct token *token, const struct resource *resource)
{
    return token->is_admin ||
           (token->subject_uid == resource->owner_uid &&
            token->tenant_id == resource->tenant_id);
}

/* Every field in request is controlled by the authenticated caller. */
int update(const struct token *token, const struct update_request *request)
{
    struct resource *resource = load_resource(request->resource_id);

    if (resource == NULL)
        return -1;
    if (!may_modify(token, resource))
        return -1;
    return store_value(resource, request->new_value, request->new_value_size);
}
