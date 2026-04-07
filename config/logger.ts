function logger() {
  let date = new Date().toLocaleString('pl-PL', {
    timeZone: 'Europe/Warsaw',
  });

  console.log(
    colors.grey(date),
    '|',
    'Account',
    colors.blue('id'),
    'has logged in from local storage.'
  );
}
