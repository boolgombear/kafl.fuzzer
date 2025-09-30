def _to_bytes(value):
    if isinstance(value, bytes):
        return value
    return str(value).encode("utf-8", "ignore")

# Nautilus grammar for generating XML-style documents.
#
# This grammar focuses on producing syntactically valid XML snippets with
# nested elements, attributes, comments, and mixed text content. It relies on
# Nautilus Python grammar semantics (ctx.rule/ctx.regex/ctx.script) and is
# intended for use with the NautilusGrammarMutator integration.

ctx.rule('START', '{Document}')

ctx.rule('Document', '{Prolog}{RootElement}')
ctx.rule('Document', '{RootElement}')

ctx.rule('Prolog', '<?xml version="1.0" encoding="UTF-8"?>')
ctx.rule('Prolog', '<?xml version="1.1" encoding="UTF-8"?>')

ctx.rule('RootElement', '{Element}')

ctx.rule('Element', '{StandardElement}')
ctx.rule('Element', '{EmptyElement}')

ctx.script('StandardElement', ['TAG_NAME', 'AttributeSequence', 'ContentList'],
    lambda tag, attrs, body: (
        (lambda tb, ab, cb: b'<%s%s>%s</%s>' % (
            tb,
            (b'' if not ab.strip() else b' ' + ab.strip()),
            cb,
            tb,
        ))(_to_bytes(tag), _to_bytes(attrs), _to_bytes(body))
    )
)

ctx.script('EmptyElement', ['TAG_NAME', 'AttributeSequence'],
    lambda tag, attrs: (
        (lambda tb, ab: b'<%s%s/>' % (
            tb,
            (b'' if not ab.strip() else b' ' + ab.strip()),
        ))(_to_bytes(tag), _to_bytes(attrs))
    )
)

ctx.script('AttributeSequence', ['Attribute', 'AttributeSequence'],
    lambda head, tail: (
        (lambda hb, tb: hb + (b' ' + tb if tb else b''))(_to_bytes(head), _to_bytes(tail))
    )
)
ctx.rule('AttributeSequence', '{Attribute}')
ctx.rule('AttributeSequence', '')

ctx.script('Attribute', ['ATTR_NAME', 'AttributeValue'],
    lambda name, value: _to_bytes(name) + b'=' + _to_bytes(value)
)

ctx.rule('AttributeValue', '"{AttributeContent}"')
ctx.rule('AttributeValue', '\'{AttributeContent}\'')

ctx.script('AttributeContent', ['AttributeContent', 'AttrFragment'],
    lambda current, fragment: _to_bytes(current) + _to_bytes(fragment)
)
ctx.rule('AttributeContent', '{AttrFragment}')

ctx.regex('AttrFragment', '[A-Za-z0-9_:\\-]{1,12}')
ctx.regex('AttrFragment', '[A-Fa-f0-9]{1,8}')
ctx.rule('AttrFragment', '{Entity}')

ctx.rule('Entity', '&amp;')
ctx.rule('Entity', '&lt;')
ctx.rule('Entity', '&gt;')
ctx.rule('Entity', '&quot;')
ctx.rule('Entity', '&apos;')

ctx.script('ContentList', ['Content', 'ContentList'],
    lambda head, tail: _to_bytes(head) + _to_bytes(tail)
)
ctx.rule('ContentList', '{Content}')
ctx.rule('ContentList', '')

ctx.rule('Content', '{TextNode}')
ctx.rule('Content', '{Element}')
ctx.rule('Content', '{Comment}')
ctx.rule('Content', '{CDataSection}')
ctx.rule('Content', '{ProcessingInstruction}')

ctx.script('TextNode', ['TextChunk', 'TextTail'],
    lambda chunk, tail: _to_bytes(chunk) + _to_bytes(tail)
)
ctx.rule('TextTail', '{TextChunk}{TextTail}')
ctx.rule('TextTail', '')

ctx.regex('TextChunk', '[A-Za-z0-9 ,\.;:\\-_]{1,16}')
ctx.rule('TextChunk', '{Entity}')
ctx.rule('TextChunk', '{Whitespace}')

ctx.rule('Whitespace', ' ')
ctx.rule('Whitespace', '\t')
ctx.rule('Whitespace', '\n')
ctx.rule('Whitespace', '\r')

ctx.rule('Comment', '<!--{CommentBody}-->')
ctx.regex('CommentBody', '[A-Za-z0-9 ,.\-]{0,24}')

ctx.script('CDataSection', ['CDataBody'],
    lambda body: b'<![CDATA[' + _to_bytes(body) + b']]>'
)
ctx.regex('CDataBody', '[A-Za-z0-9 ,\n\r\t]{0,24}')

ctx.rule('ProcessingInstruction', '<?{PIName}{PIContent}?>')
ctx.regex('PIName', '[A-Za-z_][A-Za-z0-9_.:-]{0,10}')
ctx.rule('PIContent', ' {TextChunk}')
ctx.rule('PIContent', '')

ctx.regex('TAG_NAME', '[A-Za-z_][A-Za-z0-9_.:-]{0,10}')
ctx.regex('ATTR_NAME', '[A-Za-z_][A-Za-z0-9_.:-]{0,10}')
