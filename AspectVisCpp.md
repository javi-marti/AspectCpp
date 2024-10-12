# Your first plugin: AspectVisCpp

You are writing a first approximation of an [Aspect Oriented Programming](https://en.wikipedia.org/wiki/Aspect-oriented_programming) variant of C++. The entire plugin is only about 100 lines, including boilerplate.

You will be registering custom attributes, analysing functions in the GIMPLE IR, and injecting instrumentation.

https://gcc.gnu.org/onlinedocs/gccint/Plugins.html

## Excercise 1

### Setup
You should have a rasonably recent GCC installed. e.g., in Ubuntu for GCC 11:

> sudo apt install gcc-11

Or your platform equivalent.

You should not go down [the rabbit hole](https://gcc.gnu.org/install/) of building from source. Plugin development does not require building your own GCC. Having the source at hand can be convenient, but not required for this workshop.

Confirm your installation:
```
$ gcc --version
gcc (Ubuntu 11.4.0-1ubuntu1~22.04) 11.4.0
```

The plugin development headers are available via:

> apt-get install gcc-11-plugin-dev


Make sure the version matches that of your GCC installation. In Fedora, you may also need to install `libmpc-devel` if you run into build errors later on.

To verify your installation:

> gcc -print-file-name=plugin

You should see a full path if the plugins are detected:
```
/usr/lib/gcc/x86_64-linux-gnu/11/plugin
```

### Basic plugin

Create a file `plugin.cc`:
```c++
#include <gcc-plugin.h>
#include <plugin-version.h>

int plugin_is_GPL_compatible;

int plugin_init (struct plugin_name_args *plugin_info,
             struct plugin_gcc_version *version)
{
    // standard version check
    if (!plugin_default_version_check (version, &gcc_version)) {
        fprintf(stderr, "version check: NOT OK\n");
        return 1;
    } else {
        fprintf(stderr, "version check: OK!\n");
    }

    return 0;
}
```

You can use `std::cout`, if you wish.

You wil be using this simple `Makefile`:
```Make
GCCPLUGINS_DIR:= $(shell $(CXX) --print-file-name=plugin)
CPPFLAGS+= -I$(GCCPLUGINS_DIR)/include -I. -fPIC -fno-rtti

all: plugin-build test-build

plugin-build: plugin.o
	$(CXX) $(CPPFLAGS) -shared $^ -o plugin.so 

test-build: plugin-build
	$(CXX) -fplugin=$(shell pwd)/plugin.so plugin-test.cc -o test.out

run-test:
	./test.out
	
clean:
	rm -f *o *~ *out
```

Try to building the plugin:

```
make plugin-build
```

A `plugin.so` should be produced with no erros.

Notice that we compile with `-fPIC` and `-fno-rtti`.

**Await here for some instruction discussion.**

## Exercise 2
We will now add a custom attribute to the language.

The `plugin_init` function is where the plugin can register with GCC what events it is interested in - such as a certain compiler pass. Some of these events are not program manipulation stages per-se, but artificial stages which are useful for other purposes.

One such event is `PLUGIN_ATTRIBUTES`, which we use to register custom attributes. Update your `plugin_init`:
```C++
// include all of these headers which we will be using later
#include <gcc-plugin.h>
#include <plugin-version.h>
#include <tree.h>
#include <gimple.h>
#include <tree-pass.h>
#include <gimple-iterator.h>
#include <stringpool.h>
#include <attribs.h>

static void cb_attribute_registration( void* eventData, void* userData ) {
    /* this is the [[viscon::attribute]] syntax */
    register_scoped_attributes( attrs_to_register, "viscon" /*, false */); /* api change in older versions */
}

int plugin_init(struct plugin_name_args *plugin_info, struct plugin_gcc_version *version)
{

    //[...]

    register_callback(aspect_plug_name, PLUGIN_ATTRIBUTES, &cb_attribute_registration, NULL);

    return 0;
}
```

The register call requires a callback receiving two `void*`. You could have figured this out by searching in the headers:

```
$ grep -nr 'void register_callback' /usr/lib/gcc/x86_64-linux-gnu/11/plugin/include/

/usr/lib/gcc/x86_64-linux-gnu/11/plugin/include/plugin.h:130:extern void register_callback (const char *plugin_name,
```

And in `plugin.h`:

```C++

/* Function type for a plugin callback routine.

   GCC_DATA  - event-specific data provided by GCC
   USER_DATA - plugin-specific data provided by the plugin  */

typedef void (*plugin_callback_func) (void *gcc_data, void *user_data);

// [...]

extern void register_callback (const char *plugin_name,
                               int event,
                               plugin_callback_func callback,
                               void *user_data);

```

Our callback will discard these parameters, and simply call `register_scoped_attributes`. Most documentation you will find uses `register_attributes` instead. The scoped version gives use `[[namespace::attr]]` rather than `__attribute((attr))` syntax. It is not required.

The complete attribute registration will look like this. I have brought some documentation into the code, but you can get this from looking at the headers, as usual:

```C++
#include <gcc-plugin.h>
#include <plugin-version.h>
#include <tree.h>
#include <gimple.h>
#include <tree-pass.h>
#include <gimple-iterator.h>
#include <stringpool.h>
#include <attribs.h>


int plugin_is_GPL_compatible;

static const char aspect_plug_name[] = "aspect";
static const char aspect_attr_name[] = "aspect";

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

/* The array of attribute specs passed to register_scoped_attributes must be NULL terminated */
attribute_spec attrs_to_register[] = { aspect_attr, NULL };

static void cb_attribute_registration( void* eventData, void* userData ) {

    /* this is the [[viscon::attribute]] syntax */
    register_scoped_attributes( attrs_to_register, "viscon" /*, false */); /* api change in older versions */
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

    register_callback(aspect_plug_name, PLUGIN_ATTRIBUTES, &cb_attribute_registration, NULL);

    return 0;
}
```

Take some time to understand the code. Then, to test it, create a `plugin-test.cc`:
```C++
#include <stdio.h>

[[viscon::aspect]] void foo()
{
    printf("bar enter\n");

    int x, y;

    x ^= y;
    y ^= x;
    x ^= y;

    printf("bar exit\n");
    return;
}

int main()
{
    printf("main\n");
    foo();
    return 0;
}

```

The following target builds the test propgram. You will be able to see the output messages from your plugin:
> make test-build

Then you can run the program as usual: 
> make run-test

The program should run normally, given that we have not modified it in any way.


### Exercise 3

You have already written about half of your plugin. Time to add an optimiser pass. Naturally, another callback in `plugin_init`:
```C++
register_callback(aspect_plug_name, PLUGIN_PASS_MANAGER_SETUP, NULL, &pass_info);
```

You can see all the hookable events in `plugin.def`:
```
$ grep -nr 'PLUGIN_ATTRIBUTES' /usr/lib/gcc/x86_64-linux-gnu/11/plugin/include/

/usr/lib/gcc/x86_64-linux-gnu/11/plugin/include/plugin.def:60:DEFEVENT (PLUGIN_ATTRIBUTES)
```

Our optimiser pass will require some more signficant boilerplate, but is mostly default configuration.

`PLUGIN_PASS_MANAGER_SETUP` takes no callback (second last param), but does take data (`pass_info`):

```C++
    /* the struct passed to pass manager describing an optimiser pass to register. See pass_manager.h, tree-pass.h */
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
```

You can instantiate this inside your `plugin_init` directly. The configuration simply states that our optimizer pass `aspect_opt_pass` is interested in running after the `ssa` pass. `ssa` is a pass inside GIMPLE (the IR) that simplifies the IR into Single-Static-Assignment form. This is a common place (time?) to do instrumentation, although you can do it at any stage with enough effort (even at the AST - and perhaps there is a type-safety argument in favour of that).

The optimiser pass is just a `gimple_opt_pass` class:

```C++
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

        return 0;
    }
};

```

GCC uses a macro interface to read its tree structures. Google is your friend here. `current_function_decl` and `gcc:context` are symbols exported by GCC. Add these in your global scope:

```C++
// from tree-core.h - GCC keeps track of the function we are in
extern tree current_function_decl;

// from context.h - the global GCC context
extern gcc::context *g;
```

Finally, `pass_data` is some more configuration detail for pass manager about our pass:

```C++
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
```

This simply states that our pass requires the entire GIMPLE grammar, and that pass manager should update `ssa` and `cfg` after our pass is done. This is not strictly necessary now, but will be necessary once we add instrumentation.


Try building the plugin and test. You should see the optimiser pass detecting all your functions marked with the custom attribute.

## Excercise 4

Our last step is to add instrumentation to all `aspect` functions whose name ends in `_loggable`. This requires some fiddling in the documentation to get right the first time, but is terse:

```C++
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
```

Our optimiser pass now matches on all functions marked with the `[[viscon::aspect]]` attribute whose name ends in `_loggable`, and injects a call to a funtion `__aspect_log_f` at the top of the function body.

The injected function does not exist yet. It is possible to define it within a GCC plugin, but it is much simpler to make it a library in our `aspect` programs. Update `plugin-test.cc`:
```C++
#include <stdio.h>

// our instrumentation runtime machinery
__attribute__((used)) void __aspect_log_f()
{
    printf("aspect-plugin [RUN]: instrumented\n");
}


void foo_loggable()
{
    printf("foo_loggable enter\n"); // if format string given, too long for Three Address Code single stment.

    int x, y;

    x ^= y;
    y ^= x;
    x ^= y;

    printf("foo_loggable exit\n");
    return;
}

int main()
{
    printf("main\n");
    foo_loggable();
    return 0;
}

```

That's it. Take some time to understand the code and browse documentation if you wish.

If you try building the plugin and test program now, your test program will fail to build:
```
/usr/bin/ld: /tmp/ccIaec1c.o: in function `foo_loggable()':
plugin-test.cc:(.text+0x27): undefined reference to `__aspect_log_f'
collect2: error: ld returned 1 exit status```

```

This is partially good news because the plugin has injected the function call, but the linker does not see a function named `__aspect_log_f`. Can you guess why? try removing `[[viscon::aspect]]` to stop instrumentation, build again, and look at the binary with `nm test.out` or `objdump`.

```
$ nm test.out 
000000000000038c r __abi_tag
0000000000004010 B __bss_start
0000000000004010 b completed.0
                 w __cxa_finalize@GLIBC_2.2.5
[...]
                 U __libc_start_main@GLIBC_2.34
0000000000001220 T main
                 U puts@GLIBC_2.2.5
00000000000010c0 t register_tm_clones
0000000000001060 T _start
0000000000004010 D __TMC_END__
0000000000001163 T _Z12foo_loggablev   <-------------- here
0000000000001149 T _Z14__aspect_log_fv
00000000000011e1 T _Z18no_aspect_loggablev
00000000000011a2 T _Z3barv
```

The instrumentation function is there, but the name is mangled by C++. Get rid of the mangling by giving it C linkage:

```C++
// our instrumentation runtime machinery
extern "C" {
    __attribute__((used)) void __aspect_log_f()
    {
        printf("aspect-plugin [RUN]: instrumented\n");
    }
}
```

## Congratulations
Your you AspectVisCpp is now complete. Take a moment to enjoy playing with instrumenting different functions.

If you like, you can now continue extending your plugin. Some suggestions:

- Try injecting the instrumentation right after the existing `printf` in the test function body.
- Pass the name of the instrumented function to `__aspect_log_f`.
- Use the `aspect` attribute in classes, like we discussed with `__attribute((cold))`, that lets you specify `aspect` on a class and let all member functions be `aspect` functions by default.
    - You can get inspiration for how to traverse a class members by looking at our in-tree patch that landed in GCC 14. Commit here: https://github.com/gcc-mirror/gcc/commit/4f52e61e0665e760b95975b4d49437873967be2e
    - You want to register the callback against: `PLUGIN_FINISH_TYPE`
