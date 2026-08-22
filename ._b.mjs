const { app, initForTest } = await import('./app.js');
await initForTest();
app.listen(4630, () => console.log('UP'));
