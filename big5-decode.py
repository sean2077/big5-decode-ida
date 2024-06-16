############################################################################################
##
## IDA Pro Plugin: Big5 Decode
##
## Decode bytes as Big5 at the current address
##
## Available for IDA 7+ and Python 3.8+
##
## To install:
##      Copy script into plugins directory, i.e: C:\Program Files\<ida version>\plugins
##
## To use:
##      Right-click an address and select 'Big5 Decode',
##      the decoded string will be added as a repeatable comment.
##
############################################################################################

__AUTHOR__ = "@sean2077"

PLUGIN_NAME = "Big5 Decode"
PLUGIN_HOTKEY = ""
VERSION = "1.0.0"

ACTION_PREFIX = "sean2077"

import codecs

import idaapi
import idc


def big5_decode_action():
    ea = idc.get_screen_ea()
    if ea == idaapi.BADADDR:
        idaapi.warning("Invalid address selected")
        return

    # Start reading bytes from the current address
    byte_list = []
    while True:
        byte_value = idc.get_wide_byte(ea)
        if byte_value == 0:
            break
        byte_list.append(byte_value)
        ea += 1

    # Convert byte list to byte array
    byte_array = bytearray(byte_list)

    # Decode byte array using Big5 encoding
    try:
        decoded_string = codecs.decode(byte_array, "big5")
    except Exception as e:
        idaapi.msg("Error decoding Big5: {}\n".format(e))
        return

    # Add a repeatable comment to the address
    idc.set_cmt(idc.get_screen_ea(), decoded_string, 1)
    idaapi.msg(f"Added comment: {decoded_string} at {idc.get_screen_ea()}\n")


class Big5DecodePlugin(idaapi.plugin_t):
    flags = idaapi.PLUGIN_PROC | idaapi.PLUGIN_HIDE
    comment = "Big5 Decode"
    help = "Right-click an address and select 'Big5 Decode'"
    wanted_name = PLUGIN_NAME
    wanted_hotkey = PLUGIN_HOTKEY

    def init(self):
        self._init_action_big5_decode()
        self._init_hooks()
        idaapi.msg("%s %s initialized...\n" % (self.wanted_name, VERSION))
        return idaapi.PLUGIN_KEEP

    def run(self, arg):
        idaapi.msg("%s cannot be run as a script.\n" % self.wanted_name)

    def term(self):
        self._hooks.unhook()
        self._del_action_big5_decode()
        idaapi.msg("%s terminated...\n" % self.wanted_name)

    def _init_hooks(self):
        self._hooks = Hooks()
        self._hooks.hook()

    ACTION_BIG5_DECODE = f"{ACTION_PREFIX}:big5_decode"

    def _init_action_big5_decode(self):
        action_desc = idaapi.action_desc_t(
            self.ACTION_BIG5_DECODE,
            "Big5 decode",
            IDACtxEntry(big5_decode_action),
            PLUGIN_HOTKEY,
            "Decode bytes as Big5 at the current address",
            0,
        )
        assert idaapi.register_action(action_desc), "Action registration failed"

    def _del_action_big5_decode(self):
        idaapi.unregister_action(self.ACTION_BIG5_DECODE)


class Hooks(idaapi.UI_Hooks):
    def finish_populating_widget_popup(self, widget, popup):
        inject_big5_decode_actions(widget, popup, idaapi.get_widget_type(widget))
        return 0


def inject_big5_decode_actions(form, popup, form_type):
    if form_type == idaapi.BWN_DISASM:
        idaapi.attach_action_to_popup(form, popup, Big5DecodePlugin.ACTION_BIG5_DECODE, "Big5 decode", idaapi.SETMENU_APP)
    return 0


class IDACtxEntry(idaapi.action_handler_t):
    def __init__(self, action_function):
        idaapi.action_handler_t.__init__(self)
        self.action_function = action_function

    def activate(self, ctx):
        self.action_function()
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS


def PLUGIN_ENTRY():
    return Big5DecodePlugin()
