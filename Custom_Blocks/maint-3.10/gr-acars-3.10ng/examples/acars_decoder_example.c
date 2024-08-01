// gcc -Ilibacars -Llibacars/build/libacars -o acars_decoder_example acars_decoder_example.c  -lacars-2

#include <stdbool.h>            // bool
#include <stdio.h>              // printf(3)
#include <string.h>             // strlen(3)
#include <libacars/libacars.h>  // la_proto_node, la_proto_tree_destroy(),
                                // la_proto_tree_format_text()
#include <libacars/acars.h>     // la_acars_decode_apps(), la_acars_extract_sublabel_and_mfi()
#include <libacars/vstring.h>   // la_vstring, la_vstring_destroy()

int main(int argc, char **argv) {
	char *label = "H1";
	char message[256];
	char sublabel[3];
	char mfi[3];
	la_msg_dir direction = LA_MSG_DIR_AIR2GND;
        if (argc>1) sprintf(message,argv[1]); 
        else sprintf(message,"/ACCFAYA.ADS.F-GSPY0722C6F810920343AB5C9F0C0464B5CF88200E6F10BD7E4C0F6E691CBE4C0F4F");

	// The label is H1 which means the message text contains one or two additional fields -
	// sublabel (int this case "M1") and Message Function Identifier ("B6"). These have to
	// be stripped before calling la_acars_decode_apps(). la_acars_extract_sublabel_and_mfi()
	// does this conveniently for us. It also copies these two fields to the given char buffers
	// which must have a size of at least 3 bytes).
	int offset = la_acars_extract_sublabel_and_mfi(label, direction, message,
			strlen(message), sublabel, mfi);
	char *ptr = message;
	// If the value returned by la_acars_extract_sublabel_and_mfi() is greater than 0, it means
	// that at least the sublabel has been found. The value indicates how many bytes we need
	// to skip over.
	if(offset > 0) {
		ptr += offset;
	}
	// Now look for supported ACARS application and decode it if found
	la_proto_node *node = la_acars_decode_apps(label, ptr, direction);
	if(node != NULL) {
		la_vstring *vstr = la_proto_tree_format_text(NULL, node);
		printf("Sublabel: %s MFI: %s\n", sublabel, mfi);
		printf("Decoded message:\n%s\n", vstr->str);
		la_vstring_destroy(vstr, true);
	} else {
		printf("No supported ACARS application found\n");
	}
	la_proto_tree_destroy(node);
}
