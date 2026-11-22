// baseline: two eval calls
const safe = 1;
eval(userInput);
function f(x) {
  return eval(x);
}
// sast-ignore: JS001
eval(suppressed);
