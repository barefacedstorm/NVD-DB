# NVD-DB
Search &amp; Store NVD

Searches will be saved in /JSON with unique local JSON files to refrence for each search completed.

![image](https://github.com/user-attachments/assets/474f52a2-36e1-4815-9585-3e663b4f2a39)

I have postgres imported for future plans, if you install it you will need to run the following to get the app to launch currently

sudo -u postgres psql -c "ALTER USER postgres PASSWORD 'postgres';"

sudo -u postgres createdb nvd_db
