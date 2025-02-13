package transits

// PathTraversalFunction is a global variable that will hold the function to
// test for path traversal. We cannot directly call it because then the compiler crashes.
// This is due to the fact that our code gets inserted on compile of `os`, and some code for path traversal
// Uses the `os` module resulting in a stuck compile loop.
var PathTraversalFunction func(file string) error = nil
