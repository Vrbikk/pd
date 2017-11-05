//
// Created by vrbik on 5.11.17.
//

void automataUnitTest() {
    void *automa;

    assert(automa = ndpi_init_automa());
    assert(ndpi_add_string_to_automa(automa, "hello") == 0);
    assert(ndpi_add_string_to_automa(automa, "world") == 0);
    ndpi_finalize_automa(automa);
    assert(ndpi_match_string(automa, "This is the wonderful world of nDPI") == 0);

    ndpi_free_automa(automa);
}