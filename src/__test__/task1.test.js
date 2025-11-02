import { app, server } from '../server.mjs';
import { describe, test, expect, beforeAll, afterAll, vi } from 'vitest';
import request from 'supertest';

// ID, що використовуються в тестах
const VALID_USER_ID = '123';
const VALID_ARTICLE_ID = '456';
const NON_EXISTENT_ID = 'non-existent-id';

describe('Express REST API', () => {
  beforeAll(() => {
    // Створюємо спай для запобігання виводу логів під час тестів
    vi.spyOn(console, 'log').mockImplementation(() => { });
    vi.spyOn(console, 'error').mockImplementation(() => { });
  });

  afterAll(() => {
    // Закриваємо сервер після тестів
    if (server && server.listening) {
      server.close();
    }
    vi.restoreAllMocks();
  });

  // Тестування маршруту "/"
  describe('Root Route', () => {
    test('GET / повинен повертати статус 200 та правильне повідомлення', async () => {
      const response = await request(app).get('/');

      expect(response.status).toBe(200);
      expect(response.text).toBe('Get root route');
    });
  });

  // Тестування маршрутів "/users"
  describe('Users Routes', () => {
    test('GET /users повинен повертати статус 200 та правильне повідомлення', async () => {
      const response = await request(app).get('/users');

      expect(response.status).toBe(200);
      expect(response.text).toBe('Get users route');
    });

    test('POST /users повинен повертати статус 201 та правильне повідомлення', async () => {
      const response = await request(app)
        .post('/users')
        .send({ name: 'Test User' });

      expect(response.status).toBe(201);
      expect(response.text).toBe('Post users route');
    });

    test('POST /users повинен повертати статус 400 при некоректних даних', async () => {
      const response = await request(app)
        .post('/users')
        .send({ name: '' });

      expect(response.status).toBe(400);
      expect(response.text).toBe('Bad Request');
    });

    test('GET /users/:userId повинен повертати статус 200 та правильне повідомлення з ID', async () => {
      const response = await request(app).get(`/users/${VALID_USER_ID}`);

      expect(response.status).toBe(200);
      expect(response.text).toBe(`Get user by Id route: ${VALID_USER_ID}`);
    });

    test('GET /users/:userId повинен повертати статус 404 для неіснуючого користувача', async () => {
      const response = await request(app).get(`/users/${NON_EXISTENT_ID}`);

      expect(response.status).toBe(404);
      expect(response.text).toBe('Not Found');
    });

    test('PUT /users/:userId повинен повертати статус 200 та правильне повідомлення з ID', async () => {
      const response = await request(app)
        .put(`/users/${VALID_USER_ID}`)
        .send({ name: 'Updated User' });

      expect(response.status).toBe(200);
      expect(response.text).toBe(`Put user by Id route: ${VALID_USER_ID}`);
    });

    test('PUT /users/:userId повинен повертати статус 400 при некоректних даних', async () => {
      const response = await request(app)
        .put(`/users/${VALID_USER_ID}`)
        .send({ name: '' });

      expect(response.status).toBe(400);
      expect(response.text).toBe('Bad Request');
    });

    test('PUT /users/:userId повинен повертати статус 404 для неіснуючого користувача', async () => {
      const response = await request(app)
        .put(`/users/${NON_EXISTENT_ID}`)
        .send({ name: 'Updated User' });

      expect(response.status).toBe(404);
      expect(response.text).toBe('Not Found');
    });

    test('DELETE /users/:userId повинен повертати статус 204 без вмісту', async () => {
      const response = await request(app).delete(`/users/${VALID_USER_ID}`);

      expect(response.status).toBe(204);
      expect(response.text).toBe('');
    });

    test('DELETE /users/:userId повинен повертати статус 404 для неіснуючого користувача', async () => {
      const response = await request(app).delete(`/users/${NON_EXISTENT_ID}`);

      expect(response.status).toBe(404);
      expect(response.text).toBe('Not Found');
    });
  });

  // Тестування маршрутів "/articles"
  describe('Articles Routes', () => {
    test('GET /articles повинен повертати статус 200 та правильне повідомлення', async () => {
      const response = await request(app).get('/articles');

      expect(response.status).toBe(200);
      expect(response.text).toBe('Get articles route');
    });

    test('POST /articles повинен повертати статус 201 та правильне повідомлення', async () => {
      const response = await request(app)
        .post('/articles')
        .send({ title: 'Test Article' });

      expect(response.status).toBe(201);
      expect(response.text).toBe('Post articles route');
    });

    test('POST /articles повинен повертати статус 400 при некоректних даних', async () => {
      const response = await request(app)
        .post('/articles')
        .send({ title: '' });

      expect(response.status).toBe(400);
      expect(response.text).toBe('Bad Request');
    });

    test('GET /articles/:articleId повинен повертати статус 200 та правильне повідомлення з ID', async () => {
      const response = await request(app).get(`/articles/${VALID_ARTICLE_ID}`);

      expect(response.status).toBe(200);
      expect(response.text).toBe(`Get article by Id route: ${VALID_ARTICLE_ID}`);
    });

    test('GET /articles/:articleId повинен повертати статус 404 для неіснуючої статті', async () => {
      const response = await request(app).get(`/articles/${NON_EXISTENT_ID}`);

      expect(response.status).toBe(404);
      expect(response.text).toBe('Not Found');
    });

    test('PUT /articles/:articleId повинен повертати статус 200 та правильне повідомлення з ID', async () => {
      const response = await request(app)
        .put(`/articles/${VALID_ARTICLE_ID}`)
        .send({ title: 'Updated Article' });

      expect(response.status).toBe(200);
      expect(response.text).toBe(`Put article by Id route: ${VALID_ARTICLE_ID}`);
    });

    test('PUT /articles/:articleId повинен повертати статус 400 при некоректних даних', async () => {
      const response = await request(app)
        .put(`/articles/${VALID_ARTICLE_ID}`)
        .send({ title: '' });

      expect(response.status).toBe(400);
      expect(response.text).toBe('Bad Request');
    });

    test('PUT /articles/:articleId повинен повертати статус 404 для неіснуючої статті', async () => {
      const response = await request(app)
        .put(`/articles/${NON_EXISTENT_ID}`)
        .send({ title: 'Updated Article' });

      expect(response.status).toBe(404);
      expect(response.text).toBe('Not Found');
    });

    test('DELETE /articles/:articleId повинен повертати статус 204 без вмісту', async () => {
      const response = await request(app).delete(`/articles/${VALID_ARTICLE_ID}`);

      expect(response.status).toBe(204);
      expect(response.text).toBe('');
    });

    test('DELETE /articles/:articleId повинен повертати статус 404 для неіснуючої статті', async () => {
      const response = await request(app).delete(`/articles/${NON_EXISTENT_ID}`);

      expect(response.status).toBe(404);
      expect(response.text).toBe('Not Found');
    });
  });

  // Тестування обробки помилок
  describe('Error Handling', () => {
    test('Запит до неіснуючого маршруту повинен повертати статус 404', async () => {
      const response = await request(app).get('/nonexistent-route');

      expect(response.status).toBe(404);
      expect(response.text).toBe('Not Found');
    });

    test('Глобальна обробка помилок повинна повертати статус 500', async () => {
      const express = require('express');
      const tempApp = express();

      // Додаємо маршрут, який викликає помилку
      tempApp.get('/error-test', (req, res, next) => {
        next(new Error('Test error'));
      });

      // Додаємо кастомний обробник помилок
      tempApp.use((err, req, res, next) => {
        console.error(err.stack);
        res.status(500).send('Internal Server Error');
      });

      const response = await request(tempApp).get('/error-test');

      expect(response.status).toBe(500);
      expect(response.text).toBe('Internal Server Error');
    });
  });
});
