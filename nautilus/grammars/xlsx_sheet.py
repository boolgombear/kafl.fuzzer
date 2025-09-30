import random
import string

# Helper utilities tuned to observed XLSX worksheet XML patterns.

ROW_HEIGHTS = [
    "15",
    "15.75",
    "16.5",
    "17.25",
    "18",
    "18.75",
    "19.5",
    "20.25",
    "21",
    "23.25",
]

WIDTH_VALUES = [
    "2.5",
    "3.140625",
    "3.25",
    "6.125",
    "9.28515625",
    "12.625",
    "17.625",
    "18.875",
    "19.5",
    "22.375",
    "26.625",
]

STYLE_VALUES = [str(v) for v in range(1, 65)]
S_STYLE_VALUES = [str(v) for v in range(1, 40)]
T_VALUES = ["", "s", "str", "n", "b"]
FORMULAS = [
    "SUM(A1:A10)",
    "AVERAGE(B1:B10)",
    "IF(A1>0,1,0)",
    "LEN(A1)",
    "VLOOKUP(A1,Table1,2,FALSE)",
    "A1+B1",
    "COUNTIF(A:A,\"Yes\")",
]
TEXT_VALUES = [
    "Yes",
    "No",
    "Pending",
    "Complete",
    "Review",
    "Draft",
    "Total",
    "Note",
]
GUID_PARTS = string.hexdigits.lower()


def column_name(index):
    """Convert 1-based index into Excel column letter(s)."""
    if index < 1:
        index = 1
    letters = []
    while index > 0:
        index, remainder = divmod(index - 1, 26)
        letters.append(chr(ord('A') + remainder))
    return ''.join(reversed(letters))


def random_guid():
    def block(length):
        return ''.join(random.choice(GUID_PARTS[:16]) for _ in range(length))
    return '{%s-%s-%s-%s-%s}' % (block(8), block(4), block(4), block(4), block(12))


def random_cell_ref(col_count, row_count):
    col = column_name(random.randint(1, max(1, col_count)))
    row = random.randint(1, max(1, row_count))
    return f"{col}{row}"


def random_range(col_count, row_count):
    start_col = random.randint(1, max(1, col_count))
    end_col = random.randint(start_col, max(start_col, min(col_count, start_col + random.randint(0, 5))))
    start_row = random.randint(1, max(1, row_count))
    end_row = random.randint(start_row, max(start_row, min(row_count, start_row + random.randint(0, 12))))
    return f"{column_name(start_col)}{start_row}:{column_name(end_col)}{end_row}"


def random_sqref(col_count, row_count, active_cell):
    choice = random.random()
    if choice < 0.45:
        return active_cell
    if choice < 0.8:
        return random_range(col_count, row_count)
    ranges = {active_cell}
    for _ in range(random.randint(2, 4)):
        ranges.add(random_range(col_count, row_count))
    return ' '.join(sorted(ranges))


def build_sheet_pr():
    code = f"Sheet{random.randint(1, 30)}"
    pieces = [
        f'<sheetPr codeName="{code}">',
    ]
    if random.random() < 0.3:
        color = ''.join(random.choice('0123456789ABCDEF') for _ in range(6))
        pieces.append(f'<tabColor rgb="FF{color}"/>')
    pieces.append(f'<pageSetUpPr fitToPage="{random.choice(["0", "1"])}"/>')
    if random.random() < 0.25:
        pieces.append('<outlinePr summaryBelow="1" summaryRight="1"/>')
    pieces.append('</sheetPr>')
    return ''.join(pieces)


def build_sheet_views(col_count, row_count):
    active = random_cell_ref(col_count, row_count)
    sqref = random_sqref(col_count, row_count, active)
    show_grid = random.choice(['0', '1'])
    tab_selected = ' tabSelected="1"' if random.random() < 0.4 else ''
    zoom = ''
    if random.random() < 0.3:
        top_left = random_cell_ref(col_count, row_count)
        zoom = f' topLeftCell="{top_left}" zoomScale="{random.choice([80, 100, 120, 160])}"'
    selection = f'<selection activeCell="{active}" sqref="{sqref}"/>'
    view = f'<sheetView workbookViewId="0" showGridLines="{show_grid}"{tab_selected}{zoom}>{selection}</sheetView>'
    return f'<sheetViews>{view}</sheetViews>'


def build_sheet_format_pr():
    default_height = random.choice(ROW_HEIGHTS)
    descent = random.choice(["0.25", "0.3", "0.33"])
    extra = ''
    if random.random() < 0.2:
        extra = f' defaultColWidth="{random.choice([8.43, 9.0, 9.5, 10.0, 12.0])}"'
    return f'<sheetFormatPr defaultRowHeight="{default_height}"{extra} x14ac:dyDescent="{descent}"/>'


def build_cols(col_count):
    if col_count <= 0:
        return ''
    segments = []
    idx = 1
    while idx <= col_count:
        span = random.randint(1, min(4, col_count - idx + 1))
        min_idx = idx
        max_idx = idx + span - 1
        width = random.choice(WIDTH_VALUES)
        style = random.choice(STYLE_VALUES)
        parts = [f'<col min="{min_idx}" max="{max_idx}" width="{width}" style="{style}" customWidth="1"']
        if random.random() < 0.2:
            parts.append(' hidden="1"')
        if random.random() < 0.2:
            parts.append(f' outlineLevel="{random.randint(0, 7)}"')
        parts.append('/>')
        segments.append(''.join(parts))
        idx = max_idx + 1
    return '<cols>' + ''.join(segments) + '</cols>'


def value_for_type(t_choice):
    if t_choice == 's':
        return str(random.randint(0, 400))
    if t_choice == 'str':
        return random.choice(TEXT_VALUES)
    if t_choice == 'b':
        return random.choice(['0', '1'])
    if random.random() < 0.35:
        return f"{random.uniform(-5000, 5000):.2f}"
    return str(random.randint(-10000, 10000))


def build_sheet_data(row_count, col_count):
    rows = []
    for row_index in range(1, row_count + 1):
        span = f"1:{col_count}"
        attrs = [f'r="{row_index}"', f'spans="{span}"', 'x14ac:dyDescent="0.3"']
        if random.random() < 0.45:
            attrs.append(f'ht="{random.choice(ROW_HEIGHTS)}"')
            attrs.append('customHeight="1"')
        if random.random() < 0.2:
            attrs.append(f's="{random.choice(S_STYLE_VALUES)}"')
        cells = []
        cell_total = random.randint(max(1, col_count // 2), col_count)
        used_cols = list(range(1, col_count + 1))
        random.shuffle(used_cols)
        used_cols = sorted(used_cols[:cell_total])
        for col_idx in used_cols:
            cell_ref = f"{column_name(col_idx)}{row_index}"
            attr_parts = [f'r="{cell_ref}"', f's="{random.choice(S_STYLE_VALUES)}"']
            t_choice = random.choice(T_VALUES)
            if t_choice:
                attr_parts.append(f't="{t_choice}"')
            if random.random() < 0.15:
                attr_parts.append('cm="1"')
            content_bits = []
            if random.random() < 0.25:
                formula = random.choice(FORMULAS)
                content_bits.append(f'<f>{formula}</f>')
            if random.random() < 0.8:
                content_bits.append(f'<v>{value_for_type(t_choice)}</v>')
            attr_str = ' '.join(attr_parts)
            content_str = ''.join(content_bits)
            if content_bits:
                cells.append(f'<c {attr_str}>{content_str}</c>')
            else:
                cells.append(f'<c {attr_str}/>')
        row_attr = ' '.join(attrs)
        rows.append(f'<row {row_attr}>' + ''.join(cells) + '</row>')
    return '<sheetData>' + ''.join(rows) + '</sheetData>'


def build_merge_cells(col_count, row_count):
    if random.random() >= 0.45:
        return ''
    merges = []
    for _ in range(random.randint(1, min(10, col_count))):
        merges.append(f'<mergeCell ref="{random_range(col_count, row_count)}"/>')
    return f'<mergeCells count="{len(merges)}">' + ''.join(merges) + '</mergeCells>'


def build_conditional_formatting(col_count, row_count):
    if random.random() >= 0.35:
        return ''
    sqref = random_range(col_count, row_count)
    cf_rules = []
    priorities = list(range(1, 6))
    random.shuffle(priorities)
    for priority in priorities[:random.randint(1, 2)]:
        rule_type = random.choice(['expression', 'cellIs'])
        if rule_type == 'expression':
            formula = random.choice([
                f'LEN({random_cell_ref(col_count, row_count)})>0',
                f'{random_cell_ref(col_count, row_count)}>100',
                f'SUM({random_range(col_count, row_count)})>10',
            ])
            cf_rules.append(f'<cfRule type="expression" priority="{priority}"><formula>{formula}</formula></cfRule>')
        else:
            operator = random.choice(['greaterThan', 'lessThanOrEqual', 'between'])
            formula1 = value_for_type('n')
            formula2 = value_for_type('n') if operator == 'between' else None
            rule = [f'<cfRule type="cellIs" operator="{operator}" priority="{priority}">']
            rule.append(f'<formula>{formula1}</formula>')
            if formula2 is not None:
                rule.append(f'<formula>{formula2}</formula>')
            rule.append('</cfRule>')
            cf_rules.append(''.join(rule))
    return f'<conditionalFormatting sqref="{sqref}">' + ''.join(cf_rules) + '</conditionalFormatting>'


def build_hyperlinks(col_count, row_count):
    if random.random() >= 0.2:
        return ''
    links = []
    for idx in range(1, random.randint(1, 3) + 1):
        ref = random_range(col_count, row_count)
        display = random.choice([
            'https://example.com',
            'mailto:info@example.com',
            'Sheet1!A1',
            'Documentation',
        ])
        links.append(f'<hyperlink ref="{ref}" r:id="rId{idx}" display="{display}"/>')
    return '<hyperlinks>' + ''.join(links) + '</hyperlinks>'


def build_data_validations(col_count, row_count):
    if random.random() >= 0.25:
        return ''
    validations = []
    for _ in range(random.randint(1, 3)):
        validation_type = random.choice(['list', 'whole', 'decimal'])
        operator = random.choice(['between', 'greaterThan', 'equal'])
        sqref = random_range(col_count, row_count)
        formula1 = value_for_type('n')
        formula2 = value_for_type('n') if operator == 'between' else None
        parts = [f'<dataValidation type="{validation_type}" operator="{operator}" allowBlank="1" sqref="{sqref}">']
        parts.append(f'<formula1>{formula1}</formula1>')
        if formula2 is not None:
            parts.append(f'<formula2>{formula2}</formula2>')
        parts.append('</dataValidation>')
        validations.append(''.join(parts))
    return f'<dataValidations count="{len(validations)}">' + ''.join(validations) + '</dataValidations>'


def build_page_margins():
    return '<pageMargins left="0.7" right="0.7" top="0.78740157499999996" bottom="0.78740157499999996" header="0.3" footer="0.3"/>'


def build_page_setup():
    orientation = random.choice(['portrait', 'landscape'])
    paper_size = random.choice(['1', '5', '9'])
    scale = random.choice(['75', '100', '120'])
    fit_to_width = random.randint(1, 2)
    fit_to_height = random.randint(1, 2)
    return f'<pageSetup paperSize="{paper_size}" orientation="{orientation}" scale="{scale}" fitToWidth="{fit_to_width}" fitToHeight="{fit_to_height}"/>'


def build_header_footer():
    if random.random() >= 0.3:
        return ''
    header = random.choice(['&CAnnual Calendar', '&LBudget Report', '&RTimesheet'])
    footer = random.choice(['&RPage &P of &N', '&LGenerated via kAFL', '&LConfidential'])
    return f'<headerFooter><oddHeader>{header}</oddHeader><oddFooter>{footer}</oddFooter></headerFooter>'


def build_ext_list():
    if random.random() >= 0.2:
        return ''
    return '<extLst><ext uri="{B025F937-C7B1-47ED-AAF1-9057561C3E31}" xmlns:x14="http://schemas.microsoft.com/office/spreadsheetml/2009/9/main"><x14:slicerStyles defaultSlicerStyle="SlicerStyleLight1"/></ext></extLst>'


def build_worksheet():
    col_count = random.randint(6, 24)
    row_count = random.randint(12, 80)
    dimension_ref = f"A1:{column_name(col_count)}{row_count}"

    sections = [
        build_sheet_pr(),
        f'<dimension ref="{dimension_ref}"/>',
        build_sheet_views(col_count, row_count),
        build_sheet_format_pr(),
        build_cols(col_count),
        build_sheet_data(row_count, col_count),
        build_merge_cells(col_count, row_count),
        build_conditional_formatting(col_count, row_count),
        build_data_validations(col_count, row_count),
        build_hyperlinks(col_count, row_count),
        build_page_margins(),
        build_page_setup(),
        build_header_footer(),
        build_ext_list(),
    ]

    body = ''.join(section for section in sections if section)
    worksheet_open = (
        '<worksheet '
        'xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" '
        'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships" '
        'xmlns:mc="http://schemas.openxmlformats.org/markup-compatibility/2006" '
        'xmlns:x14ac="http://schemas.microsoft.com/office/spreadsheetml/2009/9/ac" '
        'xmlns:xr="http://schemas.microsoft.com/office/spreadsheetml/2014/revision" '
        'mc:Ignorable="x14ac xr" '
        f'xr:uid="{random_guid()}">'
    )
    worksheet_close = '</worksheet>'
    xml = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>' + worksheet_open + body + worksheet_close
    return xml.encode('utf-8')


def generate_document():
    return build_worksheet()


ctx.script('WorksheetDocument', [], lambda: generate_document())
ctx.rule('START', '{WorksheetDocument}')
