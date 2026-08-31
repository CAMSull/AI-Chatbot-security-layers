from app.security.output_filter import filter_output


def test_email_addresses_are_redacted():
    result = filter_output("Contact me at student@university.edu for details.")
    assert "student@university.edu" not in result.filtered_text
    assert "REDACTED-EMAIL" in result.filtered_text
    assert "EMAIL" in result.redactions


def test_api_key_like_strings_are_redacted():
    result = filter_output("Here is your key: sk-abcdefghijklmnopqrstuvwx123456")
    assert "sk-abcdefghijklmnopqrstuvwx123456" not in result.filtered_text
    assert "SECRET" in result.redactions


def test_credit_card_like_numbers_are_redacted():
    result = filter_output("Your card number is 4111 1111 1111 1111.")
    assert "4111 1111 1111 1111" not in result.filtered_text
    assert "CARD-NUMBER" in result.redactions


def test_clean_text_is_unchanged():
    text = "The capital of France is Paris."
    result = filter_output(text)
    assert result.filtered_text == text
    assert result.redactions == []
