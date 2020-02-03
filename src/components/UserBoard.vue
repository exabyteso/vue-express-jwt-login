<template>
    <div class="hello">
        <h1>Welcome to regular users page</h1>
        <h2>{{msg}}</h2>
        <br>
        <Logout/>
    </div>
</template>

<script>
    import Logout from './Logout'
    export default {
        components: {
            Logout
        },
        data () {
            return {
                msg: 'The commoners'
            }
        }
    }
</script>

<!-- Add "scoped" attribute to limit CSS to this component only -->
<style scoped>
    h1, h2 {
        font-weight: normal;
    }
    ul {
        list-style-type: none;
        padding: 0;
    }
    li {
        display: inline-block;
        margin: 0 10px;
    }
    a {
        color: #42b983;
    }
</style>
