#include <gcc-plugin.h>
#include <plugin-version.h>
#include <tree.h>
#include <gimple.h>
#include <tree-pass.h>
#include <gimple-iterator.h>
#include <stringpool.h>
#include <attribs.h>
#include <iostream>


int plugin_is_GPL_compatible;

static const char aspect_plug_name[] = "aspect";
static const char aspect_attr_name[] = "aspect";

// from tree-core.h - GCC keeps track of the function we are in
extern tree current_function_decl;

// from context.h - the global GCC context
extern gcc::context *g;

// see aspect_attr for signature
static tree handle_instrument_attribute(tree *node, tree name, tree args, int flags, bool *no_add_attrs) {
    fprintf(stderr, "aspect attribute found\n");

    return NULL_TREE;
}

// from tree-core.h
static struct attribute_spec aspect_attr = {
    /* The name of the attribute (without any leading or trailing __),
     or NULL to mark the end of a table of attributes.  */
    .name = aspect_attr_name,

    /* The minimum length of the list of arguments of the attribute.  */
    .min_length = 0,

    /* The maximum length of the list of arguments of the attribute
     (-1 for no maximum).  */
    .max_length = 0,

    /* Whether this attribute requires a DECL.  If it does, it will be passed
     from types of DECLs, function return types and array element types to
     the DECLs, function types and array types respectively; but when
     applied to a type in any other circumstances, it will be ignored with
     a warning.  (If greater control is desired for a given attribute,
     this should be false, and the flags argument to the handler may be
     used to gain greater control in that case.)  */
    .decl_required = false,

    /* Whether this attribute requires a type.  If it does, it will be passed
     from a DECL to the type of that DECL.  */
    .type_required = false,

    /* Whether this attribute requires a function (or method) type.  If it does,
     it will be passed from a function pointer type to the target type,
     and from a function return type (which is not itself a function
     pointer type) to the function type.  */
    .function_type_required = false,

    /* Specifies if attribute affects type's identity.  */
    .affects_type_identity =false,

      /* Function to handle this attribute. NODE points to the node to which
     the attribute is to be applied.  If a DECL, it should be modified in
     place; if a TYPE, a copy should be created.  NAME is the canonicalized
     name of the attribute i.e. without any leading or trailing underscores.
     ARGS is the TREE_LIST of the arguments (which may be NULL).  FLAGS gives
     further information about the context of the attribute.  Afterwards, the
     attributes will be added to the DECL_ATTRIBUTES or TYPE_ATTRIBUTES, as
     appropriate, unless *NO_ADD_ATTRS is set to true (which should be done on
     error, as well as in any other cases when the attributes should not be
     added to the DECL or TYPE).  Depending on FLAGS, any attributes to be
     applied to another type or DECL later may be returned;
     otherwise the return value should be NULL_TREE.  This pointer may be
     NULL if no special handling is required beyond the checks implied
     by the rest of this structure.  
     
            tree (*handler) (tree *node, tree name, tree args,
                    int flags, bool *no_add_attrs); 
    */
    .handler = handle_instrument_attribute,

    /* An array of attribute exclusions describing names of other attributes
     that this attribute is mutually exclusive with.
     

     Exclusions specify the name of an attribute that's mutually exclusive with
     this one, and whether the relationship applies to the function,
     variable, or type form of the attribute.
            struct exclusions {
                const char *name;
                bool function;
                bool variable;
                bool type;
            };
     */
    .exclude = NULL
};

// A gimple optimisation pass. Interface in tree-pass.h
struct aspect_opt_pass : public gimple_opt_pass
{
    aspect_opt_pass (const pass_data& data, gcc::context *ctxt) : gimple_opt_pass (data, ctxt) {}

    /* passes only execute if gate returns true */
    bool gate (function* gate_fun) 
    {
        return true;
    }

    /* optimiser pass implementation. Called for each function. */
    unsigned int execute(function* exec_fun)
    {
        // check if the list of attributes contains our aspect attribute
        tree attr = lookup_attribute(aspect_attr_name, DECL_ATTRIBUTES(current_function_decl));

        // skip non-aspect marked functions
        if (attr == NULL_TREE)
            return 0;

        // see https://gcc.gnu.org/onlinedocs/gccint/Identifiers.html
        fprintf(stderr, "aspect-plugin [COMPILE]: found attribute %s in %s\n", 
            aspect_attr_name, IDENTIFIER_POINTER (DECL_NAME (current_function_decl)));

        if (!is_loggable(IDENTIFIER_POINTER (DECL_NAME (current_function_decl))))
            return 0;

        fprintf(stderr, "aspect-plugin [COMPILE]: instrummenting _loggable %s\n",
            IDENTIFIER_POINTER (DECL_NAME (current_function_decl)));

        // get the first basic block in the function body
        basic_block first_block = ENTRY_BLOCK_PTR_FOR_FN(cfun)->next_bb;

        // a gimple block is a sequence of statements. Get the first statement.
        gimple* first_stmt = gsi_stmt(gsi_start_bb(first_block));

        // an iterator pointing to the statement, so that we can refer to relative positions
        gimple_stmt_iterator gsi = gsi_for_stmt(first_stmt);

        // specify function signature of our instrumentation function
        tree fn_type = build_function_type_list(
                void_type_node,             // return type
                NULL_TREE                   // varargs terminator
            );           
        
        // construct the tree declaration of the instrumentation function
        tree fn_decl = build_fn_decl("__aspect_log_f", fn_type);

        // build the GIMPLE function call to instrumentaiton function
        gcall* fn_call = gimple_build_call(fn_decl, 0);

        // inject instrumentation before the first statement (top of the function)
        gsi_insert_before(&gsi, fn_call, GSI_NEW_STMT);

        return 0;
    }

private:
    bool is_loggable(const char* str) {
        if (!str)
            return false;

        const char* suffix = "_loggable";
        size_t str_len = std::strlen(str);
        size_t suffix_len = std::strlen(suffix);

        if (str_len < suffix_len)
            return false;

        return std::strcmp(str + str_len - suffix_len, suffix) == 0;
    }
};

/* The array of attribute specs passed to register_scoped_attributes must be NULL terminated */
attribute_spec attrs_to_register[] = { aspect_attr, NULL };

static void cb_attribute_registration( void* eventData, void* userData ) {

    /* this is the [[javi::attribute]] syntax */
    register_scoped_attributes( attrs_to_register, "javi" /*, false */); /* api change in older versions */
}

int plugin_init(struct plugin_name_args *plugin_info, struct plugin_gcc_version *version)
{

    // standard version check
    if (!plugin_default_version_check (version, &gcc_version)) {
        fprintf(stderr, "version check: NOT OK\n");
        return 1;
    } else {
        fprintf(stderr, "version check: OK!\n");
    }

   /* Metadata for a pass, non-varying across all instances of a pass. See tree-pass.h  */
    struct pass_data ins_pass_data = {
        /* Optimization pass type */
        .type = GIMPLE_PASS, 

        /* Terse name of the pass. */
        .name = aspect_plug_name,

        /* ignore */
        .optinfo_flags = OPTGROUP_NONE,

        /* ignore */
        .tv_id = TV_NONE,

        /* input outpyt properties. PROP_gimple_any means the pass receives entire gimple grammar */
        .properties_required = PROP_gimple_any,
        .properties_provided = 0,
        .properties_destroyed = 0,

        /* Flags indicating common sets things to do before and after. 
        
            As we are adding instrumentation at SSA, we request the compiler to update the SSA and update the call-flow-graph
        */
        .todo_flags_start = 0,
        .todo_flags_finish = TODO_update_ssa|TODO_cleanup_cfg
    };

    // the struct passed to pass manager describing an optimiser pass to register. See pass_manager.h, tree-pass.h
    struct register_pass_info pass_info = {
        /* new pass to register. Ownership described by register_pass in tree-pass.h:
        
            Registers a new pass.  [...]  The pass object is expected to have been
            allocated using operator new and the pass manager takes the ownership of
            the pass object.

                extern void register_pass (register_pass_info *); 
        */
        .pass =  new aspect_opt_pass(ins_pass_data, g),

        /* name of the reference pass for hooking up the new pass */
        .reference_pass_name = "ssa",

        /* Insert the pass at the specified instance number of the reference pass.
         Do it for every instance if it is 0.  */
        .ref_pass_instance_number = 1,

        /* how to insert the new pass:
        
            num pass_positioning_ops {
                PASS_POS_INSERT_AFTER,   // Insert after the reference pass.
                PASS_POS_INSERT_BEFORE,  // Insert before the reference pass.
                PASS_POS_REPLACE         // Replace the reference pass.
            };
        */
        .pos_op = PASS_POS_INSERT_AFTER
    };

    register_callback(aspect_plug_name, PLUGIN_PASS_MANAGER_SETUP, NULL, &pass_info);
    register_callback(aspect_plug_name, PLUGIN_ATTRIBUTES, &cb_attribute_registration, NULL);

    return 0;
}
